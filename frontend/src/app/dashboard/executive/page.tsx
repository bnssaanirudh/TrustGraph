"use client";

import { useRef } from "react";
import { motion, useInView } from "framer-motion";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, RadarChart, Radar, PolarGrid, PolarAngleAxis } from "recharts";

// ─── Data ─────────────────────────────────────────────────────────────────────
const COMPLIANCE_DATA = [
  { framework: "SOC 2 Type II", score: 58, status: "partial", color: "#f59e0b" },
  { framework: "ISO 27001", score: 72, status: "partial", color: "#f59e0b" },
  { framework: "GDPR", score: 64, status: "partial", color: "#f59e0b" },
  { framework: "PCI DSS", score: 84, status: "compliant", color: "#16c784" },
  { framework: "HIPAA", score: 91, status: "compliant", color: "#16c784" },
  { framework: "NIST CSF", score: 47, status: "non_compliant", color: "#ef4444" },
];

const OUTAGE_PREVENTION = [
  { month: "Aug", prevented: 1.2, actual: 0.2 },
  { month: "Sep", prevented: 2.8, actual: 0.5 },
  { month: "Oct", prevented: 1.5, actual: 0.1 },
  { month: "Nov", prevented: 4.1, actual: 0.8 },
  { month: "Dec", prevented: 3.2, actual: 0.3 },
  { month: "Jan", prevented: 21.1, actual: 0 },
];

const RADAR_DATA = [
  { dimension: "Detection Speed", value: 72 },
  { dimension: "Response Time", value: 58 },
  { dimension: "Coverage", value: 81 },
  { dimension: "Accuracy", value: 89 },
  { dimension: "Automation", value: 64 },
  { dimension: "Intelligence", value: 91 },
];

const PIE_DATA = [
  { name: "Compromised", value: 4, color: "#ef4444" },
  { name: "At Risk", value: 4, color: "#f59e0b" },
  { name: "Safe", value: 2, color: "#16c784" },
];

function AnimatedNumber({ value, prefix = "", suffix = "", decimals = 1 }: { value: number; prefix?: string; suffix?: string; decimals?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true });
  return (
    <div ref={ref} style={{ fontFamily: "var(--font-display)", fontSize: "3rem", lineHeight: 1, color: "var(--color-text-primary)" }}>
      {inView ? `${prefix}${value.toFixed(decimals)}${suffix}` : `${prefix}0${suffix}`}
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload) return null;
  return (
    <div style={{ background: "var(--color-surface-2)", border: "1px solid var(--color-border)", padding: "0.75rem 1rem", fontSize: "0.8125rem" }}>
      <div style={{ color: "var(--color-text-muted)", marginBottom: "0.5rem", fontSize: "0.6875rem" }}>{label}</div>
      {payload.map((p: any) => (
        <div key={p.name} style={{ color: p.fill || p.color, marginTop: "0.25rem" }}>
          {p.name}: <strong>${p.value.toFixed(1)}M</strong>
        </div>
      ))}
    </div>
  );
};

export default function ExecutivePage() {
  const handleExportPDF = () => {
    window.print();
  };

  return (
    <div>
      <div className="console-header">
        <div>
          <div style={{ fontSize: "1.125rem", fontWeight: 600, color: "var(--color-text-primary)" }}>Executive Impact Dashboard</div>
          <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: "2px" }}>Board-level security intelligence · Q1 2024</div>
        </div>
        <button
          onClick={handleExportPDF}
          style={{ padding: "0.5rem 1.25rem", background: "var(--color-surface-3)", border: "1px solid var(--color-border)", color: "var(--color-text-primary)", fontSize: "0.8125rem", fontWeight: 600, cursor: "pointer", display: "flex", alignItems: "center", gap: "0.5rem" }}
        >
          ↓ Export PDF Report
        </button>
      </div>

      <div style={{ padding: "1.5rem 2rem" }}>
        {/* ── Financial Impact Headline ─────────────────────────────────────── */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "1rem", marginBottom: "1.5rem" }}>
          {[
            { label: "Financial Blast Radius Exposure", value: "$21.1M", sub: "Quantified breach impact", color: "var(--color-compromised)", trend: "↑" },
            { label: "Outage Prevention Savings", value: "$18.3M", sub: "Estimated savings YTD", color: "var(--color-safe)", trend: "↑" },
            { label: "MTTC Improvement", value: "−34%", sub: "vs prior quarter", color: "var(--color-safe)", trend: "↓" },
            { label: "Regulatory Exposure", value: "$4.2M", sub: "Potential GDPR fines", color: "var(--color-risk)", trend: "↑" },
          ].map(({ label, value, sub, color, trend }) => (
            <motion.div
              key={label}
              className="metric-card"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <div className="metric-label">{label}</div>
              <div className="metric-value" style={{ color, marginTop: "0.75rem", fontSize: "1.75rem" }}>{value}</div>
              <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: "0.25rem" }}>{sub}</div>
            </motion.div>
          ))}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem", marginBottom: "1.5rem" }}>
          
          {/* Outage Prevention Chart */}
          <div className="panel">
            <div style={{ padding: "1rem 1.5rem", borderBottom: "1px solid var(--color-border)" }}>
              <div style={{ fontSize: "0.875rem", fontWeight: 600, color: "var(--color-text-primary)" }}>Outage Prevention Savings vs Actual Losses</div>
              <div style={{ fontSize: "0.6875rem", color: "var(--color-text-muted)", marginTop: "2px" }}>USD Millions · 6-Month Trailing</div>
            </div>
            <div style={{ padding: "1.5rem", height: "240px" }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={OUTAGE_PREVENTION} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" vertical={false} />
                  <XAxis dataKey="month" tick={{ fontSize: 10, fill: "var(--color-text-muted)" }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: "var(--color-text-muted)" }} axisLine={false} tickLine={false} tickFormatter={(v) => `$${v}M`} />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar dataKey="prevented" name="Prevention Value" fill="rgba(22,199,132,0.6)" radius={[2, 2, 0, 0]} />
                  <Bar dataKey="actual" name="Actual Losses" fill="rgba(239,68,68,0.7)" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Node Risk Distribution */}
          <div className="panel">
            <div style={{ padding: "1rem 1.5rem", borderBottom: "1px solid var(--color-border)" }}>
              <div style={{ fontSize: "0.875rem", fontWeight: 600, color: "var(--color-text-primary)" }}>Asset Risk Distribution</div>
              <div style={{ fontSize: "0.6875rem", color: "var(--color-text-muted)", marginTop: "2px" }}>GAT-classified node risk states</div>
            </div>
            <div style={{ padding: "1.5rem", height: "240px", display: "flex", alignItems: "center", gap: "2rem" }}>
              <PieChart width={160} height={160}>
                <Pie data={PIE_DATA} cx={75} cy={75} innerRadius={45} outerRadius={70} paddingAngle={3} dataKey="value" strokeWidth={0}>
                  {PIE_DATA.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
              </PieChart>
              <div style={{ flex: 1 }}>
                {PIE_DATA.map(item => (
                  <div key={item.name} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.75rem" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                      <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: item.color }} />
                      <span style={{ fontSize: "0.8125rem", color: "var(--color-text-secondary)" }}>{item.name}</span>
                    </div>
                    <span style={{ fontSize: "1rem", fontWeight: 700, color: item.color, fontFamily: "var(--font-mono)" }}>{item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Compliance Status */}
        <div className="panel" style={{ marginBottom: "1.5rem" }}>
          <div style={{ padding: "1rem 1.5rem", borderBottom: "1px solid var(--color-border)" }}>
            <div style={{ fontSize: "0.875rem", fontWeight: 600, color: "var(--color-text-primary)" }}>Regulatory Compliance Status</div>
          </div>
          <div style={{ padding: "1.5rem" }}>
            {COMPLIANCE_DATA.map(f => (
              <div key={f.framework} style={{ display: "grid", gridTemplateColumns: "180px 1fr 60px", gap: "1.5rem", alignItems: "center", marginBottom: "1.25rem" }}>
                <div style={{ fontSize: "0.875rem", color: "var(--color-text-secondary)" }}>{f.framework}</div>
                <div style={{ height: "6px", background: "var(--color-surface-3)", borderRadius: "3px", overflow: "hidden" }}>
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${f.score}%` }}
                    transition={{ duration: 0.8, delay: 0.2 }}
                    style={{ height: "100%", background: f.color, borderRadius: "3px" }}
                  />
                </div>
                <div style={{ fontSize: "0.875rem", fontWeight: 700, color: f.color, textAlign: "right", fontFamily: "var(--font-mono)" }}>{f.score}%</div>
              </div>
            ))}
          </div>
        </div>

        {/* Security Capability Radar */}
        <div className="panel">
          <div style={{ padding: "1rem 1.5rem", borderBottom: "1px solid var(--color-border)" }}>
            <div style={{ fontSize: "0.875rem", fontWeight: 600, color: "var(--color-text-primary)" }}>Security Capability Maturity</div>
          </div>
          <div style={{ padding: "1.5rem", height: "280px" }}>
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={RADAR_DATA} margin={{ top: 20, right: 30, bottom: 20, left: 30 }}>
                <PolarGrid stroke="var(--color-border)" />
                <PolarAngleAxis dataKey="dimension" tick={{ fontSize: 10, fill: "var(--color-text-muted)" }} />
                <Radar name="Maturity" dataKey="value" stroke="#58a6ff" fill="#58a6ff" fillOpacity={0.15} strokeWidth={1.5} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}
