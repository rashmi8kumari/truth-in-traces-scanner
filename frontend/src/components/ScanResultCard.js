import React from "react";
import { motion } from "framer-motion";
import "./ScanResultCard.css";

export default function ScanResultCard({ title, data }) {
  const pretty =
    typeof data === "string"
      ? data
      : JSON.stringify(data, null, 2)
          .replace(/[{}"]/g, "")
          .replace(/,/g, "");

  return (
    <motion.div
      className="result-card"
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <div className="card-head">
        <div className="card-title">{title}</div>
      </div>
      <pre className="card-body">{pretty}</pre>
    </motion.div>
  );
}

