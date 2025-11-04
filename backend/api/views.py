import os
import re
import json
import platform
import psutil
import socket
import subprocess
import requests
from datetime import datetime, timedelta
from functools import wraps
from django.contrib.auth.models import User
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status as drf_status
import jwt
from dotenv import load_dotenv

# -----------------------------
# Load environment variables
# -----------------------------
load_dotenv()

# -----------------------------
# Configuration
# -----------------------------
SECRET_KEY = "intrudex_secret_key"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_TIMEOUT = 8
MAX_CVES_PER_LOOKUP = 3


# -----------------------------
# JWT token check
# -----------------------------
def token_required(func):
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth_header:
            return Response({"error": "Authorization header missing"}, status=401)

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return Response({"error": "Invalid Authorization header"}, status=401)

        token = parts[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload.get("id"))
            request.user = user
        except jwt.ExpiredSignatureError:
            return Response({"error": "Token expired"}, status=401)
        except (jwt.InvalidTokenError, User.DoesNotExist):
            return Response({"error": "Invalid token"}, status=401)

        return func(request, *args, **kwargs)
    return wrapper


# -----------------------------
# Helper: fetch CVEs from NVD (real API)
# -----------------------------
def fetch_cves_from_nvd(keyword, max_results=MAX_CVES_PER_LOOKUP):
    """
    Fetch CVE data from NVD for a given keyword (service name like SMB, RPC etc.)
    Returns a list of CVEs with ID, description, CVSS score & severity.
    """
    if not keyword:
        return []

    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    headers = {"User-Agent": "Intrudex/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        res = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=NVD_TIMEOUT)
        if res.status_code != 200:
            print(f"⚠️ NVD API error: {res.status_code} - {res.text[:100]}")
            return []

        data = res.json()
        vulnerabilities = data.get("vulnerabilities", [])
        results = []

        for item in vulnerabilities[:max_results]:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "Unknown")
            desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "No description")

            # Prefer CVSS v3.1 > v3.0 > v2
            cvss_score, severity = None, "Unknown"
            metrics = cve.get("metrics", {})

            v3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
            if v3:
                cvss_data = v3[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "Unknown")
            elif metrics.get("cvssMetricV2"):
                v2 = metrics["cvssMetricV2"][0].get("cvssData", {})
                cvss_score = v2.get("baseScore")
                severity = "MEDIUM" if cvss_score and cvss_score >= 4 else "LOW"

            results.append({
                "cve_id": cve_id,
                "description": desc,
                "cvss_score": cvss_score,
                "severity": severity,
                "last_modified": cve.get("lastModified", "")
            })

        return results

    except requests.exceptions.Timeout:
        print("⏱️ NVD API request timed out")
        return []
    except Exception as e:
        print(f"❌ Error fetching CVEs for {keyword}: {e}")
        return []


# -----------------------------
# Auth: Register / Login
# -----------------------------
@api_view(["POST"])
def register_user(request):
    username, email, password = request.data.get("username"), request.data.get("email"), request.data.get("password")
    if not username or not email or not password:
        return Response({"error": "All fields required"}, status=400)
    if User.objects.filter(username=username).exists():
        return Response({"error": "User already exists"}, status=400)

    user = User.objects.create_user(username=username, email=email, password=password)
    payload = {"id": user.id, "exp": datetime.utcnow() + timedelta(hours=24), "iat": datetime.utcnow()}
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return Response({"token": token, "message": "User registered successfully"}, status=201)


@api_view(["POST"])
def login_user(request):
    username, password = request.data.get("username"), request.data.get("password")
    try:
        user = User.objects.get(username=username)
        if not user.check_password(password):
            raise User.DoesNotExist
        payload = {"id": user.id, "exp": datetime.utcnow() + timedelta(hours=24), "iat": datetime.utcnow()}
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return Response({"token": token, "message": "Login successful"}, status=200)
    except User.DoesNotExist:
        return Response({"error": "Invalid credentials"}, status=401)


# -----------------------------
# Main: System Scan (with NVD)
# -----------------------------
@api_view(["GET"])
@token_required
def scan_system(request):
    try:
        # 1️⃣ System Info
        system_info = {
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.architecture(),
            "processor": platform.processor(),
            "hostname": socket.gethostname(),
            "ip_address": socket.gethostbyname(socket.gethostname()),
        }

        # 2️⃣ Installed Software
        try:
            result = subprocess.check_output("wmic product get Name,Version", shell=True, text=True)
            installed_software = result.splitlines()[1:40]
        except Exception:
            installed_software = ["Unable to fetch software list"]

        # 3️⃣ Open Ports
        try:
            open_ports = sorted({conn.laddr.port for conn in psutil.net_connections(kind="inet")
                                 if conn.status == "LISTEN" and conn.laddr})
        except Exception:
            open_ports = []

        # 4️⃣ Firewall Rules
        try:
            fw_raw = subprocess.check_output(
                'powershell -Command "Get-NetFirewallRule | Select-Object DisplayName,Action | ConvertTo-Json -Depth 2"',
                shell=True, text=True
            )
            fw_data = json.loads(fw_raw)
            firewall_rules = [f"{r.get('DisplayName')} ({r.get('Action')})" for r in fw_data[:20]]
        except Exception:
            firewall_rules = ["Firewall info unavailable"]

        # 5️⃣ Vulnerability Detection + CVE from NVD
        port_vuln_map = {135: "RPC", 139: "NetBIOS", 445: "SMB", 3389: "RDP", 3306: "MySQL", 21: "FTP", 22: "SSH"}
        vulnerabilities = []
        total = critical = high = medium = low = 0

        for port in open_ports:
            if port in port_vuln_map:
                service = port_vuln_map[port]
                cves = fetch_cves_from_nvd(service)

                for cve in cves:
                    total += 1
                    score = cve.get("cvss_score") or 0
                    if isinstance(score, (int, float)):
                        if score >= 9:
                            critical += 1
                        elif score >= 7:
                            high += 1
                        elif score >= 4:
                            medium += 1
                        else:
                            low += 1

                vulnerabilities.append({
                    "port": port,
                    "service": service,
                    "message": f"{service} detected on port {port}.",
                    "cve_details": cves
                })

        # 6️⃣ Malware Check (basic)
        malware_signatures = ["trojan", "virus", "worm", "malware"]
        infected_files = []
        try:
            for root, _, files in os.walk("C:\\ProgramData"):
                for f in files:
                    if any(sig in f.lower() for sig in malware_signatures):
                        infected_files.append(os.path.join(root, f))
                if len(infected_files) > 10:
                    break
            malware_check = (
                f"⚠️ {len(infected_files)} suspicious files found!\n\nSample:\n" + "\n".join(infected_files[:5])
                if infected_files else "✅ System appears clean. No malware detected."
            )
        except Exception:
            malware_check = "Malware scan failed or permission denied."

        # 7️⃣ Patch Status
        try:
            patch_raw = subprocess.check_output(
                'powershell -Command "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 | ConvertTo-Json"',
                shell=True, text=True
            )
            patch_info = json.loads(patch_raw)
            patch_date = patch_info.get("InstalledOn", "Unknown")
            patch_status = f"Latest patch: {patch_info.get('Description', 'Unknown')} (Installed on: {patch_date})"
        except Exception:
            patch_status = "Unable to fetch patch information"

        # 8️⃣ System Health Summary
        system_health = 100
        summary = []

        if "⚠️" in malware_check:
            system_health -= 25
            summary.append("Malware detected")
        else:
            summary.append("Malware clean")

        if "Unable" in patch_status:
            system_health -= 15
            summary.append("Patch status unknown")
        else:
            summary.append("Patches up-to-date")

        if len(open_ports) > 10:
            system_health -= 15
            summary.append(f"Many open ports ({len(open_ports)})")
        else:
            summary.append("Port configuration normal")

        if total > 5:
            system_health -= 20
            summary.append(f"High vulnerabilities: {total}")
        else:
            summary.append("Minimal vulnerabilities")

        # 9️⃣ Final Report
        report = {
            "user": request.user.username,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "system_info": system_info,
            "installed_software": installed_software,
            "open_ports": open_ports,
            "firewall_rules": firewall_rules,
            "vulnerabilities": vulnerabilities,
            "malware_check": malware_check,
            "patch_status": patch_status,
            "system_health": f"{system_health}%",
            "vulnerability_summary": summary,
            "total_vulnerabilities": {
                "total": total,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
            "recommendation": (
                "Patch critical vulnerabilities and update outdated software."
                if total > 0 else "System appears secure."
            ),
        }

        return Response(report, status=200)

    except Exception as e:
        return Response({"error": str(e)}, status=500)

