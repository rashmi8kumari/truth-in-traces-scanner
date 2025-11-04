import requests
from django.conf import settings

def fetch_cve_from_nvd(service_name):
    """
    Fetch top CVEs from NVD API based on service name (e.g., 'SMB', 'RPC', etc.)
    """
    api_key = getattr(settings, "NVD_API_KEY", None)
    if not api_key:
        return []

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service_name}&resultsPerPage=5"
    headers = {"apiKey": api_key}

    try:
        res = requests.get(url, headers=headers, timeout=15)
        res.raise_for_status()
        data = res.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})

            cves.append({
                "cve_id": cve.get("id"),
                "description": cve.get("descriptions", [{}])[0].get("value", ""),
                "cvss_score": metrics.get("baseScore", "N/A"),
                "severity": metrics.get("baseSeverity", "Unknown"),
                "last_modified": cve.get("lastModified", "N/A")
            })

        return cves

    except Exception as e:
        print("Error fetching CVE:", e)
        return []
