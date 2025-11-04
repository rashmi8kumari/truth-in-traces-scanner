import React, { useState, useEffect } from "react";
import Navbar from "./components/Navbar";
import LoginRegister from "./components/LoginRegister";
import ScanDashboard from "./components/ScanDashboard";
import "./App.css";

function App() {
  const [token, setToken] = useState(localStorage.getItem("intrudex_token") || null);

  useEffect(() => {
    if (token) localStorage.setItem("intrudex_token", token);
    else localStorage.removeItem("intrudex_token");
  }, [token]);

  return (
    <div className="app-root">
      <Navbar token={token} onLogout={() => setToken(null)} />
      <main className="main-area">
        {!token ? (
          <LoginRegister onAuth={(tok) => setToken(tok)} />
        ) : (
          <ScanDashboard token={token} />
        )}
      </main>
      <footer className="footer">Intrudex • Built to Protect </footer>
    </div>
  );
}

export default App;


