"use client";

import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from "recharts";

// ─── Types ────────────────────────────────────────────────────────────────────
type Severity = "critical" | "high" | "medium" | "low";

interface VendorAlert {
  id: string; vendor: string; threat: string; severity: Severity;
  blastRadius: number; financialImpact: number; detectedAt: string;
  mitreTechniques: string[]; affectedNodes: number; status: string;
}

// ─── Data ─────────────────────────────────────────────────────────────────────
const TELEMETRY_DATA = Array.from({ length: 24 }, (_, i) => ({
  time: `${String(i).padStart(2, "0")}:00`,
  apiVolume: Math.floor(800 + Math.random() * 1200 + (i > 8 && i < 11 ? 8000 : 0)),
  anomalies: Math.floor(5 + Math.random() * 20 + (i > 8 && i < 11 ? 280 : 0)),
}));

const VENDOR_ALERTS: VendorAlert[] = [
  { id: "t1", vendor: "VendorX API Solutions", threat: "Session Token Lateral Movement — DB Auth Schema", severity: "critical", blastRadius: 0.92, financialImpact: 6500000, detectedAt: "08:55", mitreTechniques: ["T1550.001", "T1021"], affectedNodes: 6, status: "active" },
  { id: "t2", vendor: "VendorX API Solutions", threat: "Unauthorized PII Database Access — Mass Exfiltration", severity: "critical", blastRadius: 0.95, financialImpact: 7800000, detectedAt: "10:15", mitreTechniques: ["T1530", "T1213"], affectedNodes: 4, status: "active" },
  { id: "t3", vendor: "VendorX API Solutions", threat: "API Gateway Session Token Reuse", severity: "critical", blastRadius: 0.89, financialImpact: 4200000, detectedAt: "08:23", mitreTechniques: ["T1190", "T1078"], affectedNodes: 5, status: "active" },
  { id: "t4", vendor: "Acme Cloud Services", threat: "Container Privilege Escalation — svc-cluster-7", severity: "high", blastRadius: 0.68, financialImpact: 1800000, detectedAt: "09:41", mitreTechniques: ["T1611", "T1548"], affectedNodes: 3, status: "active" },
  { id: "t5", vendor: "PayStream Financial", threat: "Suspicious API Volume Spike — 75x Baseline", severity: "high", blastRadius: 0.71, financialImpact: 1200000, detectedAt: "11:02", mitreTechniques: ["T1499", "T1110"], affectedNodes: 2, status: "investigating" },
  { id: "t6", vendor: "Logistix Supply Chain", threat: "API Key Rotation Overdue — 93 Days Lapsed", severity: "medium", blastRadius: 0.35, financialImpact: 120000, detectedAt: "06:30", mitreTechniques: ["M1017"], affectedNodes: 1, status: "monitoring" },
];

// ─── Sub-components ───────────────────────────────────────────────────────────
function TrustGauge({ value }: { value: number }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDash = (value / 100) * circumference;
  const color = value < 40 ? "var(--color-compromised)" : value < 65 ? "var(--color-risk)" : "var(--color-safe)";

  return (
    <div style={{ position: "relative", width: "140px", height: "140px", margin: "0 auto" }}>
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r={radius} fill="none" stroke="var(--color-surface-3)" strokeWidth="8" />
        <motion.circle
          cx="70" cy="70" r={radius}
          fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: circumference - strokeDash }}
          transition={{ duration: 1.4, ease: "easeOut" }}
          strokeLinecap="round"
          transform="rotate(-90 70 70)"
        />
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
          style={{ fontFamily: "var(--font-display)", fontSize: "2rem", color, lineHeight: 1 }}
        >
          {value}
        </motion.div>
        <div style={{ fontSize: "0.5625rem", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "var(--color-text-muted)", marginTop: "2px" }}>TRUST INDEX</div>
      </div>
    </div>
  );
}

function MetricCard({ label, value, sub, color, trend }: { label: string; value: string; sub?: string; color?: string; trend?: "up" | "down" | "neutral" }) {
  return (
    <motion.div
      className="metric-card"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ borderColor: "var(--color-border-bright)" }}
    >
      <div className="metric-label">{label}</div>
      <div className="metric-value" style={{ color: color || "var(--color-text-primary)", marginTop: "0.75rem" }}>
        {value}
      </div>
      {sub && <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: "0.25rem" }}>{sub}</div>}
    </motion.div>
  );
}

// ─── Custom Tooltip ───────────────────────────────────────────────────────────
const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload) return null;
  return (
    <div style={{ background: "var(--color-surface-2)", border: "1px solid var(--color-border)", padding: "0.75rem 1rem", fontSize: "0.8125rem" }}>
      <div style={{ color: "var(--color-text-muted)", marginBottom: "0.5rem", fontSize: "0.6875rem" }}>{label}</div>
      {payload.map((p: any) => (
        <div key={p.name} style={{ color: p.color, display: "flex", gap: "1rem", justifyContent: "space-between" }}>
          <span>{p.name}</span><span style={{ fontWeight: 600 }}>{p.value.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
};

// ─── Expanded Row ─────────────────────────────────────────────────────────────
function ExpandedAlertRow({ alert }: { alert: VendorAlert }) {
  return (
    <motion.tr
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
    >
      <td colSpan={7} style={{ padding: 0 }}>
        <div style={{ background: "var(--color-surface-2)", padding: "1.25rem 1.5rem", borderBottom: "1px solid var(--color-border)" }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "1.5rem" }}>
            <div>
              <div className="section-label" style={{ color: "var(--color-text-muted)", fontSize: "0.5625rem", marginBottom: "0.375rem" }}>MITRE ATT&CK</div>
              <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                {alert.mitreTechniques.map(t => (
                  <span key={t} style={{ padding: "0.2rem 0.5rem", background: "rgba(88,166,255,0.1)", color: "var(--color-text-accent)", fontSize: "0.6875rem", fontFamily: "var(--font-mono)", borderRadius: "2px" }}>{t}</span>
                ))}
              </div>
            </div>
            <div>
              <div className="section-label" style={{ color: "var(--color-text-muted)", fontSize: "0.5625rem", marginBottom: "0.375rem" }}>BLAST RADIUS</div>
              <div style={{ height: "6px", background: "var(--color-surface-3)", borderRadius: "3px", overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${alert.blastRadius * 100}%`, background: alert.blastRadius > 0.7 ? "var(--color-compromised)" : "var(--color-risk)", borderRadius: "3px" }} />
              </div>
              <div style={{ fontSize: "0.75rem", color: "var(--color-text-secondary)", marginTop: "0.25rem" }}>{(alert.blastRadius * 100).toFixed(0)}% surface</div>
            </div>
            <div>
              <div className="section-label" style={{ color: "var(--color-text-muted)", fontSize: "0.5625rem", marginBottom: "0.375rem" }}>AFFECTED NODES</div>
              <div style={{ fontSize: "1.5rem", fontFamily: "var(--font-display)", color: "var(--color-text-primary)" }}>{alert.affectedNodes}</div>
            </div>
            <div>
              <div className="section-label" style={{ color: "var(--color-text-muted)", fontSize: "0.5625rem", marginBottom: "0.375rem" }}>FINANCIAL IMPACT</div>
              <div style={{ fontSize: "1rem", fontWeight: 600, color: "var(--color-compromised)" }}>${(alert.financialImpact / 1000000).toFixed(1)}M</div>
            </div>
          </div>
        </div>
      </td>
    </motion.tr>
  );
}

// ─── Main Dashboard View ──────────────────────────────────────────────────────
export default function DashboardPage() {
  const [selectedAlert, setSelectedAlert] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => setTick(t => t + 1), 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div>
      {/* ── Console Header ────────────────────────────────────────────────── */}
      <div className="console-header">
        <div>
          <div style={{ fontSize: "1.125rem", fontWeight: 600, color: "var(--color-text-primary)" }}>System Health & Operations</div>
          <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: "2px" }}>
            Live telemetry • {new Date().toUTCString().slice(0, 25)}
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <span className="risk-dot compromised" />
          <span style={{ fontSize: "0.75rem", color: "var(--color-text-secondary)", fontFamily: "var(--font-mono)" }}>INCIDENT ACTIVE</span>
        </div>
      </div>

      <div style={{ padding: "1.5rem 2rem" }}>
        {/* ── Top Metrics Ribbon ────────────────────────────────────────────── */}
        <div style={{ display: "grid", gridTemplateColumns: "160px repeat(4, 1fr)", gap: "1rem", marginBottom: "1.5rem" }}>
          {/* Trust Gauge */}
          <motion.div
            className="metric-card"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            style={{ display: "flex", alignItems: "center", justifyContent: "center" }}
          >
            <TrustGauge value={34.7} />
          </motion.div>
          
          <MetricCard label="Vendor Vulnerabilities" value="5" sub="3 critical active" color="var(--color-compromised)" />
          <MetricCard label="Active CARAG Loops" value="3" sub="Iteration 2/4 running" color="var(--color-risk)" />
          <MetricCard label="Isolated Blast Radius" value="6" sub="Nodes under containment" color="var(--color-isolated)" />
          <MetricCard label="MTTC" value="127m" sub="Mean Time to Containment" />
        </div>

        {/* ── Telemetry Chart ───────────────────────────────────────────────── */}
        <div className="panel" style={{ marginBottom: "1.5rem" }}>
          <div style={{ padding: "1rem 1.5rem", borderBottom: "1px solid var(--color-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ fontSize: "0.875rem", fontWeight: 600, color: "var(--color-text-primary)" }}>Vendor API Volume vs Anomaly Events — 24h</div>
            <div style={{ display: "flex", gap: "1rem" }}>
              <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", fontSize: "0.6875rem", color: "var(--color-text-secondary)" }}>
                <div style={{ width: "10px", height: "2px", background: "#58a6ff" }} />API Volume
              </div>
              <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", fontSize: "0.6875rem", color: "var(--color-text-secondary)" }}>
                <div style={{ width: "10px", height: "2px", background: "var(--color-compromised)" }} />Anomalies
              </div>
            </div>
          </div>
          <div style={{ padding: "1.5rem", height: "240px" }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={TELEMETRY_DATA} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
                <defs>
                  <linearGradient id="apiGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#58a6ff" stopOpacity={0.15}/>
                    <stop offset="95%" stopColor="#58a6ff" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="anomalyGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" vertical={false} />
                <XAxis dataKey="time" tick={{ fontSize: 10, fill: "var(--color-text-muted)", fontFamily: "var(--font-mono)" }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 10, fill: "var(--color-text-muted)" }} tickLine={false} axisLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="apiVolume" name="API Volume" stroke="#58a6ff" strokeWidth={1.5} fill="url(#apiGrad)" />
                <Area type="monotone" dataKey="anomalies" name="Anomalies" stroke="#ef4444" strokeWidth={2} fill="url(#anomalyGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* ── Vendor Alert Table ────────────────────────────────────────────── */}
        <div className="panel">
          <div style={{ padding: "1rem 1.5rem", borderBottom: "1px solid var(--color-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ fontSize: "0.875rem", fontWeight: 600, color: "var(--color-text-primary)" }}>Active Vendor Alert Inventory</div>
            <div style={{ display: "flex", gap: "0.5rem" }}>
              {["Critical: 3", "High: 2", "Medium: 1"].map((badge, i) => (
                <span key={badge} className={`risk-badge ${i === 0 ? "compromised" : i === 1 ? "at_risk" : "safe"}`}>{badge}</span>
              ))}
            </div>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Vendor</th>
                <th>Threat</th>
                <th>Severity</th>
                <th>Blast Radius</th>
                <th>Financial Impact</th>
                <th>Detected</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {VENDOR_ALERTS.map(alert => (
                <React.Fragment key={alert.id}>
                  <tr
                    onClick={() => setSelectedAlert(selectedAlert === alert.id ? null : alert.id)}
                    className={selectedAlert === alert.id ? "selected" : ""}
                  >
                    <td style={{ color: "var(--color-text-primary)", fontWeight: 500 }}>{alert.vendor}</td>
                    <td style={{ maxWidth: "280px" }}>{alert.threat}</td>
                    <td><span className={`risk-badge ${alert.severity === "critical" ? "compromised" : alert.severity === "high" ? "at_risk" : "safe"}`}>{alert.severity}</span></td>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                        <div style={{ height: "4px", width: "60px", background: "var(--color-surface-3)", borderRadius: "2px", overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${alert.blastRadius * 100}%`, background: alert.blastRadius > 0.8 ? "var(--color-compromised)" : alert.blastRadius > 0.6 ? "var(--color-risk)" : "var(--color-safe)" }} />
                        </div>
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>{(alert.blastRadius * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td style={{ color: "var(--color-compromised)", fontWeight: 600 }}>${(alert.financialImpact / 1000000).toFixed(1)}M</td>
                    <td style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--color-text-muted)" }}>{alert.detectedAt} UTC</td>
                    <td>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.6875rem", color: alert.status === "active" ? "var(--color-compromised)" : alert.status === "investigating" ? "var(--color-risk)" : "var(--color-text-muted)" }}>
                        {alert.status.toUpperCase()}
                      </span>
                    </td>
                  </tr>
                  {selectedAlert === alert.id && <ExpandedAlertRow key={`exp-${alert.id}`} alert={alert} />}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
