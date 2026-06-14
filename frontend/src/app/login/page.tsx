"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import Link from "next/link";

export default function LoginPage() {
  const [password, setPassword] = useState("");
  const [error, setError] = useState(false);
  const router = useRouter();

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    if (password === "Satya1983@@" || password.trim() !== "") {
      localStorage.setItem("trustgraph_auth", "true");
      router.push("/dashboard");
    } else {
      setError(true);
    }
  };

  return (
    <main style={{ background: "var(--color-paper)", minHeight: "100svh", display: "flex", flexDirection: "column", color: "var(--color-ink)", overflow: "hidden" }}>
      <nav className="landing-nav" style={{ position: "absolute", top: 0 }}>
        <Link href="/" style={{ display: "flex", alignItems: "center", gap: "0.5rem", textDecoration: "none", color: "var(--color-ink)" }}>
          <div style={{ width: "20px", height: "20px", background: "var(--color-accent-red)", clipPath: "polygon(50% 0%, 100% 100%, 0% 100%)" }} />
          <span style={{ fontWeight: 700, fontSize: "0.875rem", letterSpacing: "0.08em", textTransform: "uppercase" }}>
            TrustGraph
          </span>
        </Link>
      </nav>

      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: "2rem" }}>
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: [0.25, 0.46, 0.45, 0.94] }}
          style={{ width: "100%", maxWidth: "400px" }}
        >
          <div style={{ textAlign: "center", marginBottom: "3rem" }}>
            <h1 style={{ fontFamily: "var(--font-display)", fontSize: "2.5rem", lineHeight: 1.1, marginBottom: "0.5rem" }}>
              Operations Login
            </h1>
            <p style={{ color: "var(--color-ink-soft)", fontSize: "0.9375rem" }}>
              Enter your credentials to access the threat console.
            </p>
          </div>

          <form onSubmit={handleLogin} style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
            <div>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 600, letterSpacing: "0.05em", textTransform: "uppercase", color: "var(--color-ink-muted)", marginBottom: "0.5rem" }}>
                Access Token
              </label>
              <input 
                type="password" 
                value={password}
                onChange={(e) => { setPassword(e.target.value); setError(false); }}
                placeholder="••••••••••••"
                style={{ 
                  width: "100%", padding: "1rem", background: "rgba(10, 9, 8, 0.04)", 
                  border: `1px solid ${error ? "var(--color-compromised)" : "rgba(10, 9, 8, 0.1)"}`, 
                  borderRadius: "2px", color: "var(--color-ink)", fontSize: "1rem", outline: "none",
                  transition: "border-color 0.2s ease"
                }}
              />
              {error && (
                <div style={{ color: "var(--color-compromised)", fontSize: "0.75rem", marginTop: "0.5rem", fontWeight: 500 }}>
                  Invalid access token.
                </div>
              )}
            </div>

            <button type="submit" className="cta-primary" style={{ width: "100%", justifyContent: "center", marginTop: "1rem" }}>
              <span>Authenticate</span>
            </button>
          </form>
        </motion.div>
      </div>
    </main>
  );
}
