"use client";

import { useState, Fragment } from "react";
import { motion, AnimatePresence } from "framer-motion";

const VENDORS = [
  { id: "vendor_vendorx", name: "VendorX API Solutions", category: "API Integration", country: "🇺🇸 United States", riskScore: 91.2, riskState: "compromised", apiKeyRotations: 2, lastRotation: "2023-11-01", cryptoStandard: "TLS1.2/RC4", dataVolumeGb: 2340.5, privilegeLevel: 4, anomalyCount: 47, graphDepth: 6, soc2: "non_compliant", iso27001: "non_compliant", gdpr: "partial", contact: "security@vendorx.com" },
  { id: "vendor_paystream", name: "PayStream Financial", category: "Payment Processing", country: "🇸🇬 Singapore", riskScore: 78.9, riskState: "at_risk", apiKeyRotations: 4, lastRotation: "2023-12-15", cryptoStandard: "TLS1.3/AES256", dataVolumeGb: 1205.3, privilegeLevel: 4, anomalyCount: 21, graphDepth: 4, soc2: "partial", iso27001: "compliant", gdpr: "under_review", contact: "security@paystream.sg" },
  { id: "vendor_acme", name: "Acme Cloud Services", category: "Cloud Infrastructure", country: "🇩🇪 Germany", riskScore: 62.4, riskState: "at_risk", apiKeyRotations: 12, lastRotation: "2024-01-01", cryptoStandard: "TLS1.3/AES256", dataVolumeGb: 890.2, privilegeLevel: 3, anomalyCount: 8, graphDepth: 3, soc2: "compliant", iso27001: "partial", gdpr: "compliant", contact: "security@acme-cloud.de" },
  { id: "vendor_logistix", name: "Logistix Supply Chain", category: "Logistics & Supply", country: "🇯🇵 Japan", riskScore: 55.7, riskState: "at_risk", apiKeyRotations: 8, lastRotation: "2023-10-01", cryptoStandard: "TLS1.3/AES256", dataVolumeGb: 678.4, privilegeLevel: 2, anomalyCount: 12, graphDepth: 2, soc2: "compliant", iso27001: "partial", gdpr: "under_review", contact: "security@logistix.co.jp" },
  { id: "vendor_databridge", name: "DataBridge Analytics", category: "Data Analytics", country: "🇬🇧 United Kingdom", riskScore: 44.1, riskState: "safe", apiKeyRotations: 24, lastRotation: "2024-01-10", cryptoStandard: "TLS1.3/AES256", dataVolumeGb: 445.8, privilegeLevel: 2, anomalyCount: 3, graphDepth: 2, soc2: "compliant", iso27001: "compliant", gdpr: "compliant", contact: "security@databridge.co.uk" },
  { id: "vendor_secureauth", name: "SecureAuth Identity", category: "Identity & Access", country: "🇳🇱 Netherlands", riskScore: 28.3, riskState: "safe", apiKeyRotations: 36, lastRotation: "2024-01-12", cryptoStandard: "TLS1.3/ChaCha20", dataVolumeGb: 122.9, privilegeLevel: 5, anomalyCount: 1, graphDepth: 1, soc2: "compliant", iso27001: "compliant", gdpr: "compliant", contact: "security@secureauth.nl" },
];

const COMPLIANCE_STYLE: Record<string, { color: string; label: string }> = {
  compliant: { color: "var(--color-safe)", label: "✓ Compliant" },
  non_compliant: { color: "var(--color-compromised)", label: "✗ Non-Compliant" },
  partial: { color: "var(--color-risk)", label: "~ Partial" },
  under_review: { color: "var(--color-text-muted)", label: "⟳ Under Review" },
};

function VendorDetailPanel({ vendor, onClose }: { vendor: typeof VENDORS[0]; onClose: () => void }) {
  const riskColor = vendor.riskState === "compromised" ? "var(--color-compromised)" : vendor.riskState === "at_risk" ? "var(--color-risk)" : "var(--color-safe)";

  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: "auto" }}
      exit={{ opacity: 0, height: 0 }}
      style={{ overflow: "hidden" }}
    >
      <tr>
        <td colSpan={8}>
          <div style={{ background: "var(--color-surface-2)", padding: "1.5rem 2rem", borderBottom: "1px solid var(--color-border)" }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "2rem" }}>
              {/* Risk Score Visualization */}
              <div>
                <div className="section-label" style={{ color: "var(--color-text-muted)", fontSize: "0.5625rem", marginBottom: "0.75rem" }}>RISK AGGREGATION SCORE</div>
                <div style={{ fontFamily: "var(--font-display)", fontSize: "3rem", color: riskColor, lineHeight: 1 }}>{vendor.riskScore}</div>
                <div style={{ height: "4px", background: "var(--color-surface-3)", borderRadius: "2px", marginTop: "0.75rem", overflow: "hidden" }}>
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${vendor.riskScore}%` }}
                    transition={{ duration: 0.8 }}
                    style={{ height: "100%", background: riskColor, borderRadius: "2px" }}
                  />
                </div>
              </div>
              
              {/* Compliance */}
              <div>
                <div className="section-label" style={{ color: "var(--color-text-muted)", fontSize: "0.5625rem", marginBottom: "0.75rem" }}>COMPLIANCE STATUS</div>
                {[["SOC2", vendor.soc2], ["ISO 27001", vendor.iso27001], ["GDPR", vendor.gdpr]].map(([std, status]) => {
                  const style = COMPLIANCE_STYLE[status] || COMPLIANCE_STYLE.under_review;
                  return (
                    <div key={std} style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.5rem" }}>
                      <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>{std}</span>
                      <span style={{ fontSize: "0.75rem", fontWeight: 600, color: style.color }}>{style.label}</span>
                    </div>
                  );
                })}
              </div>

              {/* Data Access */}
              <div>
                <div className="section-label" style={{ color: "var(--color-text-muted)", fontSize: "0.5625rem", marginBottom: "0.75rem" }}>DATA ACCESS</div>
                <div style={{ fontSize: "1.75rem", fontFamily: "var(--font-display)", color: "var(--color-text-primary)", marginBottom: "0.25rem" }}>
                  {vendor.dataVolumeGb >= 1000 ? `${(vendor.dataVolumeGb / 1000).toFixed(1)} TB` : `${vendor.dataVolumeGb.toFixed(0)} GB`}
                </div>
                <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>Total data access volume</div>
                <div style={{ marginTop: "0.75rem", fontSize: "0.75rem", color: "var(--color-text-secondary)" }}>
                  Crypto: <span style={{ fontFamily: "var(--font-mono)", color: vendor.cryptoStandard.includes("RC4") ? "var(--color-compromised)" : "var(--color-safe)" }}>{vendor.cryptoStandard}</span>
                </div>
              </div>

              {/* Graph Footprint */}
              <div>
                <div className="section-label" style={{ color: "var(--color-text-muted)", fontSize: "0.5625rem", marginBottom: "0.75rem" }}>GRAPH DEPENDENCY</div>
                <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem" }}>
                  {Array.from({ length: Math.min(vendor.graphDepth, 6) }, (_, i) => (
                    <div key={i} style={{ width: "24px", height: "24px", borderRadius: "50%", background: i === 0 ? riskColor : `${riskColor}${Math.floor(255 * (1 - i / 6)).toString(16).padStart(2, "0")}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: "0.5rem", color: "#fff" }}>{i + 1}</div>
                  ))}
                </div>
                <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>{vendor.graphDepth} downstream hop depth</div>
                <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: "0.25rem" }}>Privilege Level: {vendor.privilegeLevel}/5</div>
                <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: "0.25rem" }}>Contact: <a href={`mailto:${vendor.contact}`} style={{ color: "var(--color-text-accent)", textDecoration: "none" }}>{vendor.contact}</a></div>
              </div>
            </div>
          </div>
        </td>
      </tr>
    </motion.div>
  );
}

export default function VendorsPage() {
  const [selectedVendor, setSelectedVendor] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<"riskScore" | "dataVolumeGb" | "anomalyCount">("riskScore");
  
  const sorted = [...VENDORS].sort((a, b) => (b[sortBy] as number) - (a[sortBy] as number));

  return (
    <div>
      <div className="console-header">
        <div>
          <div style={{ fontSize: "1.125rem", fontWeight: 600, color: "var(--color-text-primary)" }}>Vendor Risk Management</div>
          <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: "2px" }}>{VENDORS.length} third-party providers · 3 requiring immediate action</div>
        </div>
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
          <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>Sort by:</span>
          {(["riskScore", "dataVolumeGb", "anomalyCount"] as const).map(s => (
            <button key={s} onClick={() => setSortBy(s)} style={{ padding: "0.375rem 0.75rem", border: "1px solid var(--color-border)", background: sortBy === s ? "var(--color-surface-3)" : "transparent", color: sortBy === s ? "var(--color-text-primary)" : "var(--color-text-muted)", fontSize: "0.6875rem", cursor: "pointer" }}>
              {s === "riskScore" ? "Risk Score" : s === "dataVolumeGb" ? "Data Volume" : "Anomalies"}
            </button>
          ))}
        </div>
      </div>

      <div style={{ padding: "1.5rem 2rem" }}>
        {/* Summary Cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "1rem", marginBottom: "1.5rem" }}>
          {[
            { label: "Total Vendors", value: VENDORS.length, color: "var(--color-text-primary)" },
            { label: "Compromised", value: VENDORS.filter(v => v.riskState === "compromised").length, color: "var(--color-compromised)" },
            { label: "At Risk", value: VENDORS.filter(v => v.riskState === "at_risk").length, color: "var(--color-risk)" },
            { label: "Compliant (SOC2)", value: VENDORS.filter(v => v.soc2 === "compliant").length, color: "var(--color-safe)" },
          ].map(({ label, value, color }) => (
            <div key={label} className="metric-card">
              <div className="metric-label">{label}</div>
              <div className="metric-value" style={{ color, marginTop: "0.5rem" }}>{value}</div>
            </div>
          ))}
        </div>

        {/* Vendor Table */}
        <div className="panel">
          <table className="data-table" style={{ width: "100%" }}>
            <thead>
              <tr>
                <th>Vendor</th>
                <th>Category</th>
                <th>Risk Score</th>
                <th>API Key Rotations</th>
                <th>Data Volume</th>
                <th>Anomalies</th>
                <th>SOC2</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map(vendor => (
                <Fragment key={vendor.id}>
                  <tr
                    onClick={() => setSelectedVendor(selectedVendor === vendor.id ? null : vendor.id)}
                    className={selectedVendor === vendor.id ? "selected" : ""}
                  >
                    <td>
                      <div style={{ fontWeight: 600, color: "var(--color-text-primary)", marginBottom: "2px" }}>{vendor.name}</div>
                      <div style={{ fontSize: "0.6875rem", color: "var(--color-text-muted)" }}>{vendor.country}</div>
                    </td>
                    <td>{vendor.category}</td>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                        <span style={{ fontFamily: "var(--font-mono)", fontWeight: 700, color: vendor.riskScore > 75 ? "var(--color-compromised)" : vendor.riskScore > 50 ? "var(--color-risk)" : "var(--color-safe)" }}>{vendor.riskScore}</span>
                        <div style={{ height: "4px", width: "50px", background: "var(--color-surface-3)", borderRadius: "2px", overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${vendor.riskScore}%`, background: vendor.riskScore > 75 ? "var(--color-compromised)" : vendor.riskScore > 50 ? "var(--color-risk)" : "var(--color-safe)" }} />
                        </div>
                      </div>
                    </td>
                    <td>
                      <span style={{ fontFamily: "var(--font-mono)", color: vendor.apiKeyRotations < 5 ? "var(--color-compromised)" : vendor.apiKeyRotations < 12 ? "var(--color-risk)" : "var(--color-safe)" }}>
                        {vendor.apiKeyRotations}x
                      </span>
                      <div style={{ fontSize: "0.625rem", color: "var(--color-text-muted)" }}>Last: {vendor.lastRotation}</div>
                    </td>
                    <td style={{ fontFamily: "var(--font-mono)", fontSize: "0.8125rem" }}>
                      {vendor.dataVolumeGb >= 1000 ? `${(vendor.dataVolumeGb/1000).toFixed(1)} TB` : `${vendor.dataVolumeGb.toFixed(0)} GB`}
                    </td>
                    <td>
                      <span style={{ color: vendor.anomalyCount > 20 ? "var(--color-compromised)" : vendor.anomalyCount > 8 ? "var(--color-risk)" : "var(--color-safe)", fontWeight: 600 }}>
                        {vendor.anomalyCount}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: "0.75rem", fontWeight: 600, color: COMPLIANCE_STYLE[vendor.soc2]?.color }}>
                        {COMPLIANCE_STYLE[vendor.soc2]?.label}
                      </span>
                    </td>
                    <td>
                      <span className={`risk-badge ${vendor.riskState}`}>
                        <span className={`risk-dot ${vendor.riskState}`} />
                        {vendor.riskState.replace("_", " ")}
                      </span>
                    </td>
                  </tr>
                  {selectedVendor === vendor.id && (
                    <VendorDetailPanel key={`detail-${vendor.id}`} vendor={vendor} onClose={() => setSelectedVendor(null)} />
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
