import React, { useState } from "react";
import api from "../utils/api";
import { motion } from "framer-motion";
import "./LoginRegister.css";

export default function LoginRegister({ onAuth }) {
  const [mode, setMode] = useState("login"); // 'login' or 'register'
  const [form, setForm] = useState({ username: "", email: "", password: "" });
  const [loading, setLoading] = useState(false);

  const change = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const register = async () => {
    setLoading(true);
    try {
      await api.post("register/", {
        username: form.username,
        email: form.email,
        password: form.password,
      });
      alert("Registration successful! Please login now.");
      setMode("login"); // ✅ switch to login screen
      setForm({ username: form.username, email: "", password: "" });
    } catch (e) {
      alert(e?.response?.data?.error || "Registration failed");
    }
    setLoading(false);
  };

  const login = async () => {
    setLoading(true);
    try {
      const res = await api.post("login/", {
        username: form.username,
        password: form.password,
      });
      onAuth(res.data.token);
    } catch (e) {
      alert(e?.response?.data?.error || "Login failed");
    }
    setLoading(false);
  };

  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <h2 className="neon">INTRUDEX</h2>
        <p className="muted">Consent-first Vulnerability Scanner</p>

        <div className="toggle-row">
          <button
            className={`pill ${mode === "login" ? "active" : ""}`}
            onClick={() => setMode("login")}
          >
            Login
          </button>
          <button
            className={`pill ${mode === "register" ? "active" : ""}`}
            onClick={() => setMode("register")}
          >
            Register
          </button>
        </div>

        <div className="fields">
          <input
            name="username"
            placeholder="Username"
            value={form.username}
            onChange={change}
          />
          {mode === "register" && (
            <input
              name="email"
              placeholder="Email"
              value={form.email}
              onChange={change}
            />
          )}
          <input
            name="password"
            type="password"
            placeholder="Password"
            value={form.password}
            onChange={change}
          />
        </div>

        <motion.div whileTap={{ scale: 0.98 }}>
          <button
            className="action-btn"
            onClick={mode === "login" ? login : register}
            disabled={loading}
          >
            {loading
              ? "Processing..."
              : mode === "login"
              ? "Login"
              : "Register & Continue"}
          </button>
        </motion.div>

        <small className="consent">
          By registering, you consent to run local read-only scans.
        </small>
      </div>
      <div className="matrix-side">
        <MatrixRain />
      </div>
    </div>
  );
}

// lightweight matrix component
function MatrixRain() {
  const cols = Array.from({ length: 40 });
  return (
    <div className="matrix">
      {cols.map((_, i) => (
        <div key={i} className="matrix-column">
          <span style={{ animationDelay: `${(i % 6) * 0.2}s` }}>
            {randomString()}
          </span>
        </div>
      ))}
    </div>
  );
}

function randomString() {
  const chars = "01";
  return Array.from({ length: 30 })
    .map(() => chars[Math.floor(Math.random() * 2)])
    .join("");
}
