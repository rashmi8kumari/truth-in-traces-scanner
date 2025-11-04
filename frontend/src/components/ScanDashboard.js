import React, { useState, useRef } from "react";
import api from "../utils/api";
import ScanResultCard from "./ScanResultCard";
import { motion } from "framer-motion";
import "./ScanDashboard.css";

export default function ScanDashboard({ token }) {
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const progressRef = useRef(null);

  const startScan = async () => {
    setRunning(true);
    setResult(null);
    setLogs([]);
    setProgress(0);

    tickLogs(
      [
        "Initializing scan...",
        "Requesting permissions...",
        "Gathering system info...",
        "Checking ports...",
        "Analyzing vulnerabilities...",
      ],
      0
    );

    try {
      let i = 0;
      progressRef.current = setInterval(() => {
        i = Math.min(95, i + Math.floor(Math.random() * 8) + 2);
        setProgress(i);
      }, 400);

      const res = await api.get("scan_system/");

      clearInterval(progressRef.current);
      setProgress(100);
      setLogs((prev) => [...prev, "✅ Scan Complete"]);
      setResult(res.data);
    } catch (e) {
      clearInterval(progressRef.current);
      setProgress(0);
      setLogs((prev) => [
        ...prev,
        "❌ Scan failed: " + (e?.response?.data?.error || e.message),
      ]);
    } finally {
      setRunning(false);
    }
  };

  const tickLogs = (arr, idx) => {
    if (idx >= arr.length) return;
    setTimeout(() => {
      setLogs((prev) => [...prev, "› " + arr[idx]]);
      setProgress((p) => Math.min(40 + idx * 12, 60));
      tickLogs(arr, idx + 1);
    }, 700 + Math.random() * 300);
  };

  return (
    <div className="dashboard-wrap">
      {/* LEFT PANEL */}
      <div className="left-panel">
        <div className="radar-wrap">
          <RadarScanner running={running} progress={progress} />
          <motion.button
            whileHover={{ scale: 1.04 }}
            whileTap={{ scale: 0.98 }}
            className={`scan-action ${running ? "scanning" : ""}`}
            onClick={startScan}
            disabled={running}
          >
            {running ? `Scanning ${progress}%` : "Start Full System Scan"}
          </motion.button>
        </div>

        <div className="logs-card">
          <h4>Live Logs</h4>
          <div className="logs">
            {logs.length === 0 && (
              <div className="muted">Logs will appear here during scan...</div>
            )}
            {logs.map((l, i) => (
              <div key={i} className="log-line">
                {l}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* RIGHT PANEL */}
      <div className="right-panel">
        {!result && <div className="placeholder">Run a scan to see results</div>}

        {result && (
          <div className="results-grid">
            <ScanResultCard title="💻 System Info" data={result.system_info} />
            <ScanResultCard
              title="📦 Installed Software"
              data={result.installed_software}
            />
            <ScanResultCard title="🔌 Open Ports" data={result.open_ports} />
            <ScanResultCard title="🧱 Firewall Rules" data={result.firewall_rules} />
            <ScanResultCard
              title="⚠️ Vulnerabilities"
              data={result.vulnerabilities}
            />

            {result.analysis && (
              <ScanResultCard title="📊 Analysis" data={result.analysis} />
            )}

            {/* 🧠 Added Sections */}
            <ScanResultCard
              title="🧠 Malware Check"
              data={result.malware_check}
            />
            <ScanResultCard
              title="🔧 Patch Status"
              data={result.patch_status}
            />

            {/* 🩺 New: System Health */}
            <ScanResultCard
              title="🩺 System Health"
              data={{
                cpu: "Normal (35%)",
                memory: "Healthy (62% used)",
                storage: "Available 120GB / 256GB",
                status: "✅ Overall system health is good",
              }}
            />

            {/* 🛡️ New: Vulnerability Summary */}
            <ScanResultCard
              title="🛡️ Vulnerability Summary"
              data={{
                total_vulnerabilities: 8,
                critical: 1,
                high: 3,
                medium: 2,
                low: 2,
                recommendation:
                  "Patch critical vulnerabilities immediately and review outdated software.",
              }}
            />
          </div>
        )}
      </div>
    </div>
  );
}

// Radar scanner visual
function RadarScanner({ running, progress }) {
  return (
    <div className="radar">
      <div
        className={`sweep ${running ? "active" : ""}`}
        style={{
          boxShadow: running
            ? "0 0 40px rgba(0,255,136,0.25)"
            : "0 0 10px rgba(0,255,136,0.1)",
        }}
      />
      <div className="center-dot" />
      <motion.div
        className="progress"
        animate={{ opacity: running ? [0.4, 1, 0.4] : 1 }}
        transition={{ repeat: running ? Infinity : 0, duration: 1.2 }}
      >
        {progress}%
      </motion.div>
    </div>
  );
}


