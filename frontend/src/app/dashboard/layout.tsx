"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import { useEffect } from "react";

const NAV_ITEMS = [
  { href: "/dashboard", label: "System Health", icon: "◉", shortLabel: "Health" },
  { href: "/dashboard/investigation", label: "Threat Investigation", icon: "⚡", shortLabel: "Investigate" },
  { href: "/dashboard/graph", label: "Graph Topology", icon: "⬡", shortLabel: "Graph" },
  { href: "/dashboard/vendors", label: "Vendor Risk", icon: "◈", shortLabel: "Vendors" },
  { href: "/dashboard/executive", label: "Executive Impact", icon: "◆", shortLabel: "Executive" },
  { href: "/dashboard/settings", label: "Settings & Config", icon: "⚙", shortLabel: "Settings" },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [sidebarExpanded] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    const auth = localStorage.getItem("trustgraph_auth");
    if (!auth) {
      router.push("/login");
    } else {
      setIsAuthenticated(true);
    }
  }, [router]);

  if (!isAuthenticated) return null; // Avoid hydration mismatch

  return (
    <div className="console-body" style={{ display: "flex" }}>
      {/* ── Sidebar ─────────────────────────────────────────────────────────── */}
      <aside className="console-sidebar">
        {/* Logo */}
        <div style={{ padding: "1.5rem 1.25rem 1rem", borderBottom: "1px solid var(--color-border)" }}>
          <Link href="/" style={{ textDecoration: "none", display: "flex", alignItems: "center", gap: "0.625rem" }}>
            <div style={{ width: "18px", height: "18px", background: "var(--color-accent-red)", clipPath: "polygon(50% 0%, 100% 100%, 0% 100%)", flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 700, fontSize: "0.8125rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-text-primary)" }}>TrustGraph</div>
              <div style={{ fontSize: "0.625rem", color: "var(--color-text-muted)", letterSpacing: "0.06em", marginTop: "1px" }}>SECURITY OPS</div>
            </div>
          </Link>
        </div>

        {/* Live Status Pill */}
        <div style={{ padding: "0.75rem 1.25rem", borderBottom: "1px solid var(--color-border)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", padding: "0.5rem 0.75rem", background: "rgba(239, 68, 68, 0.08)", border: "1px solid rgba(239, 68, 68, 0.2)", borderRadius: "2px" }}>
            <span className="risk-dot compromised" />
            <span style={{ fontSize: "0.6875rem", fontWeight: 600, color: "var(--color-compromised)", letterSpacing: "0.08em" }}>ACTIVE INCIDENT</span>
          </div>
        </div>

        {/* Navigation Items */}
        <nav style={{ flex: 1, padding: "0.75rem 0" }}>
          <div className="section-label" style={{ padding: "0.5rem 1.25rem 0.375rem", color: "var(--color-text-muted)", fontSize: "0.5625rem" }}>
            Operations
          </div>
          {NAV_ITEMS.map((item) => {
            const isActive = pathname === item.href || (item.href !== "/dashboard" && pathname.startsWith(item.href));
            return (
              <Link key={item.href} href={item.href} className={`nav-item ${isActive ? "active" : ""}`}>
                <span style={{ fontSize: "0.875rem", opacity: 0.8 }}>{item.icon}</span>
                <span>{item.label}</span>
                {isActive && (
                  <motion.div
                    layoutId="nav-indicator"
                    style={{ position: "absolute", right: "0.75rem", width: "4px", height: "4px", background: "var(--color-accent-red)", borderRadius: "50%" }}
                  />
                )}
              </Link>
            );
          })}
        </nav>

        {/* Bottom Status */}
        <div style={{ borderTop: "1px solid var(--color-border)", padding: "1rem 1.25rem" }}>
          <div style={{ marginBottom: "0.75rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.375rem" }}>
              <span style={{ fontSize: "0.6875rem", color: "var(--color-text-muted)" }}>Global Trust Index</span>
              <span style={{ fontSize: "0.6875rem", fontWeight: 600, color: "var(--color-compromised)" }}>34.7</span>
            </div>
            <div style={{ height: "3px", background: "var(--color-surface-3)", borderRadius: "2px", overflow: "hidden" }}>
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: "34.7%" }}
                transition={{ duration: 1.2, ease: "easeOut" }}
                style={{ height: "100%", background: "var(--color-compromised)", borderRadius: "2px" }}
              />
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem" }}>
            <div>
              <div style={{ fontSize: "0.6875rem", color: "var(--color-text-muted)" }}>CARAG Loops</div>
              <div style={{ fontSize: "0.9375rem", fontWeight: 600, color: "var(--color-text-primary)" }}>3</div>
            </div>
            <div>
              <div style={{ fontSize: "0.6875rem", color: "var(--color-text-muted)" }}>Critical Alerts</div>
              <div style={{ fontSize: "0.9375rem", fontWeight: 600, color: "var(--color-compromised)" }}>5</div>
            </div>
          </div>
        </div>
      </aside>

      {/* ── Main Content Area ────────────────────────────────────────────────── */}
      <main className="console-main" style={{ flex: 1, minHeight: "100vh" }}>
        <AnimatePresence mode="wait">
          <motion.div
            key={pathname}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.25, ease: "easeOut" }}
          >
            {children}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}
