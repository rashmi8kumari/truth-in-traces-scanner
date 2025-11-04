import React from "react";
import "./Navbar.css";

export default function Navbar({ token, onLogout }) {
  return (
    <nav className="nav">
      <div className="nav-left">
        <div className="logo">INTRUDEX</div>
        <div className="subtitle">Truth In Traces</div>
      </div>
      <div className="nav-right">
        {token ? (
          <button className="btn ghost" onClick={onLogout}>Logout</button>
        ) : (
          <div className="status-pill">Guest</div>
        )}
      </div>
    </nav>
  );
}

