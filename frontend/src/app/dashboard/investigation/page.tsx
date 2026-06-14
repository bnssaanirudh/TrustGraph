"use client";

import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";

// ─── CARAG Log Entry Types ────────────────────────────────────────────────────
interface LogEntry {
  id: string; sequence: number; stage: string; timestamp: string;
  action: string; detail: string; confidenceScore?: number;
  isCritical?: boolean; isSuccess?: boolean;
}

interface TimelineEvent {
  id: string; time: string; title: string; type: "breach" | "detection" | "hunt" | "containment";
  node: string; description: string;
}

// ─── Static CARAG Log Data ────────────────────────────────────────────────────
const INITIAL_LOGS: LogEntry[] = [
  { id: "l1", sequence: 1, stage: "planning", timestamp: "10:55:17", action: "THREAT_COORDINATE_IDENTIFICATION", detail: "CRITICAL: Threat Intel Feed flags VendorX API Gateway exploit vector. Session tokens reused across 4 distinct IP addresses — lateral movement initiation confirmed.", isCritical: true },
  { id: "l2", sequence: 2, stage: "retrieving", timestamp: "10:55:31", action: "SPLUNK_MCP_DISPATCH", detail: "ACTION: Dispatching Retriever Agent via Splunk MCP Server with initial query. Time window: 24h. SPL targeting: ambient network telemetry and authentication events." },
  { id: "l3", sequence: 3, stage: "evaluating", timestamp: "10:55:48", action: "RELEVANCE_GRADING", detail: "EVALUATION: Logs fetched — 23 records. Grader evaluates context relevance score: 0.41 (Below threshold 0.85). Reason: Query targeted ambient network telemetry instead of egress authentications.", confidenceScore: 0.41 },
  { id: "l4", sequence: 4, stage: "refining", timestamp: "10:56:02", action: "SPL_REFORMULATION", detail: "CORRECTION: Reformulating SPL query. Shifting scope to look for session-token lateral movement on database authentication schemas. Expanding time horizon x2. Adding IAM and OAuth2 sourcetypes." },
  { id: "l5", sequence: 5, stage: "retrieving", timestamp: "10:56:17", action: "SPLUNK_MCP_DISPATCH", detail: "ACTION: Re-dispatching to Splunk MCP. Refined SPL: index=trustgraph_security sourcetype=iam OR sourcetype=oauth2 | where action IN (TOKEN_USE, SESSION_EXTEND) | stats dc(src_ip) as unique_ips by session_id." },
  { id: "l6", sequence: 6, stage: "evaluating", timestamp: "10:56:35", action: "RELEVANCE_GRADING", detail: "EVALUATION: Second retrieval — 41 records. Confidence score: 0.72 (Below threshold 0.85). Anomaly rate: 68%. 28 high-severity records. Routing back for further refinement.", confidenceScore: 0.72 },
  { id: "l7", sequence: 7, stage: "refining", timestamp: "10:56:49", action: "SPL_REFORMULATION", detail: "CORRECTION: Pivoting to database audit log sourcetypes for deeper access pattern analysis. Injecting exclusion filters: removing health-check traffic, monitoring service accounts." },
  { id: "l8", sequence: 8, stage: "retrieving", timestamp: "10:57:04", action: "SPLUNK_MCP_DISPATCH", detail: "ACTION: Final retrieval — SPL targeting db_audit sourcetype. Session token ID eyJhbGciOiJSUzI1NiJ9 traced from API gateway to prod-db-01 authentication event." },
  { id: "l9", sequence: 9, stage: "evaluating", timestamp: "10:57:22", action: "RELEVANCE_GRADING", detail: "SUCCESS: Confidence score 0.91 exceeds threshold 0.85. 47,000 unauthorized SELECT queries confirmed. 3 blast radius nodes locked. Routing to Mitigator.", confidenceScore: 0.91, isSuccess: true },
  { id: "l10", sequence: 10, stage: "mitigating", timestamp: "10:57:38", action: "THREAT_CONTAINMENT_ASSEMBLY", detail: "SUCCESS: GAT risk propagation matches high-volume lateral database access logs. Blast radius locked — 6 nodes. Mitigation plan: revoke VendorX API key, suspend svc_account_7 IAM role, isolate customer_pii DB. 4 actions auto-executable.", isSuccess: true },
];

const TIMELINE_EVENTS: TimelineEvent[] = [
  { id: "e1", time: "06:00", title: "External Credential Compromise", type: "breach", node: "VendorX API Gateway", description: "VendorX service account credentials exfiltrated via phishing. Credential stuffing begins." },
  { id: "e2", time: "08:23", title: "API Gateway Session Token Abuse", type: "breach", node: "node_api_gw", description: "47 anomalous auth events. Session token reuse across 4 IP blocks." },
  { id: "e3", time: "08:47", title: "SSH Lateral Movement Initiated", type: "breach", node: "web-prod-01", description: "21 suspicious SSH auth events from VendorX IP block. Credential relay confirmed." },
  { id: "e4", time: "09:37", title: "Container Escape — svc-cluster-7", type: "breach", node: "svc-cluster-7", description: "EXEC commands outside IAM boundary. Host path mount attempted." },
  { id: "e5", time: "10:15", title: "PII Database Access — 47K Queries", type: "breach", node: "customer_pii", description: "280x query baseline. 1GB data staged for egress. GDPR breach confirmed." },
  { id: "e6", time: "10:55", title: "CARAG Hunt Loop Initiated", type: "hunt", node: "CARAG Engine", description: "LangGraph pipeline triggered. PlannerNode identifies entry coordinates." },
  { id: "e7", time: "10:57", title: "Blast Radius Locked — Confidence 0.91", type: "detection", node: "TrustGraph GAT", description: "3 CARAG iterations. 6 nodes identified. Mitigation plan assembled." },
  { id: "e8", time: "10:08", title: "Runtime Containment Applied", type: "containment", node: "IAM / Network", description: "API key revoked. IAM role suspended. DB isolation enforced. Blast radius contained." },
];

// ─── Stage Color Map ──────────────────────────────────────────────────────────
const STAGE_COLOR: Record<string, string> = {
  planning: "var(--color-text-accent)",
  retrieving: "#a371f7",
  evaluating: "#ffa657",
  refining: "#f0883e",
  mitigating: "var(--color-safe)",
  complete: "var(--color-safe)",
};

const EVENT_COLOR: Record<string, string> = {
  breach: "var(--color-compromised)",
  detection: "var(--color-risk)",
  hunt: "var(--color-text-accent)",
  containment: "var(--color-safe)",
};

// ─── Main Component ───────────────────────────────────────────────────────────
export default function InvestigationPage() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [currentLogIndex, setCurrentLogIndex] = useState(0);
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null);
  const ledgerRef = useRef<HTMLDivElement>(null);

  // Stream logs with typing effect simulation
  useEffect(() => {
    if (!isRunning) return;
    if (currentLogIndex >= INITIAL_LOGS.length) { setIsRunning(false); return; }
    const delay = 800 + Math.random() * 1200;
    const timeout = setTimeout(() => {
      setLogs(prev => [...prev, INITIAL_LOGS[currentLogIndex]]);
      setCurrentLogIndex(i => i + 1);
      if (ledgerRef.current) {
        ledgerRef.current.scrollTop = ledgerRef.current.scrollHeight;
      }
    }, delay);
    return () => clearTimeout(timeout);
  }, [isRunning, currentLogIndex]);

  const startHunt = () => {
    setLogs([]);
    setCurrentLogIndex(0);
    setIsRunning(true);
  };

  return (
    <div>
      <div className="console-header">
        <div>
          <div style={{ fontSize: "1.125rem", fontWeight: 600, color: "var(--color-text-primary)" }}>Threat Investigation Console</div>
          <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: "2px" }}>CARAG Agent Decision Ledger · Live Execution Trace</div>
        </div>
        <div style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.6875rem", color: "var(--color-text-muted)" }}>
            Confidence Threshold: 0.85 · Max Iterations: 4
          </div>
          <button
            onClick={startHunt}
            disabled={isRunning}
            style={{ padding: "0.5rem 1.25rem", background: isRunning ? "var(--color-surface-3)" : "var(--color-accent-red)", color: "#fff", border: "none", fontSize: "0.8125rem", fontWeight: 600, letterSpacing: "0.06em", cursor: isRunning ? "not-allowed" : "pointer", opacity: isRunning ? 0.6 : 1, transition: "all 0.2s" }}
          >
            {isRunning ? "⟳ HUNTING..." : "▶ LAUNCH CARAG HUNT"}
          </button>
        </div>
      </div>

      <div style={{ padding: "1.5rem 2rem", display: "grid", gridTemplateRows: "1fr auto", gap: "1.5rem", height: "calc(100vh - 80px)" }}>
        
        {/* ── TOP: Agent Decision Ledger ─────────────────────────────────────── */}
        <div className="panel" style={{ overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <div style={{ padding: "0.75rem 1.25rem", borderBottom: "1px solid var(--color-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "0.8125rem", fontWeight: 600, color: "var(--color-text-primary)" }}>Agent Decision Ledger</span>
            <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
              {isRunning && (
                <motion.div animate={{ opacity: [1, 0.3, 1] }} transition={{ duration: 1, repeat: Infinity }}>
                  <span className="risk-badge compromised">● LIVE</span>
                </motion.div>
              )}
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.6875rem", color: "var(--color-text-muted)" }}>
                {logs.length}/{INITIAL_LOGS.length} entries
              </span>
            </div>
          </div>
          
          <div
            ref={ledgerRef}
            className="terminal-ledger"
            style={{ flex: 1, overflowY: "auto" }}
          >
            {logs.length === 0 && (
              <div style={{ color: "var(--color-text-muted)", fontFamily: "var(--font-mono)", fontSize: "0.8125rem" }}>
                {`>`} Awaiting CARAG hunt initialization...
                <br />
                {`>`} Click "LAUNCH CARAG HUNT" to begin investigation loop.
              </div>
            )}
            
            <AnimatePresence>
              {logs.map((log) => (
                <motion.div
                  key={log.id}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="log-line"
                  style={{ borderLeft: log.isCritical ? "2px solid var(--color-compromised)" : log.isSuccess ? "2px solid var(--color-safe)" : "none", paddingLeft: (log.isCritical || log.isSuccess) ? "0.75rem" : undefined }}
                >
                  <span className="log-timestamp">{log.timestamp}</span>
                  <span className={`log-stage ${log.stage}`} style={{ color: STAGE_COLOR[log.stage] }}>
                    [{log.stage.toUpperCase().slice(0, 6)}]
                  </span>
                  <span className={`log-message ${log.isCritical ? "critical" : log.isSuccess ? "success" : ""}`}>
                    {log.detail}
                    {log.confidenceScore !== undefined && (
                      <span style={{ marginLeft: "0.75rem", padding: "0.1rem 0.4rem", background: log.confidenceScore >= 0.85 ? "rgba(22,199,132,0.15)" : "rgba(245,158,11,0.15)", color: log.confidenceScore >= 0.85 ? "var(--color-safe)" : "var(--color-risk)", fontFamily: "var(--font-mono)", fontSize: "0.7rem", borderRadius: "2px" }}>
                        conf: {log.confidenceScore}
                      </span>
                    )}
                  </span>
                </motion.div>
              ))}
            </AnimatePresence>
            
            {isRunning && (
              <motion.div
                animate={{ opacity: [1, 0] }}
                transition={{ duration: 0.7, repeat: Infinity, repeatType: "reverse" }}
                style={{ color: "var(--color-text-accent)", fontFamily: "var(--font-mono)", fontSize: "0.875rem" }}
              >
                ▊
              </motion.div>
            )}
          </div>
        </div>

        {/* ── BOTTOM: Incident Timeline ──────────────────────────────────────── */}
        <div className="panel" style={{ height: "280px", overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <div style={{ padding: "0.75rem 1.25rem", borderBottom: "1px solid var(--color-border)" }}>
            <span style={{ fontSize: "0.8125rem", fontWeight: 600, color: "var(--color-text-primary)" }}>Security Incident Timeline — Jan 15, 2024</span>
          </div>
          <div style={{ flex: 1, padding: "1.25rem", overflowX: "auto", overflowY: "hidden" }}>
            <div style={{ position: "relative", minWidth: "900px" }}>
              {/* Timeline rail */}
              <div style={{ height: "2px", background: "var(--color-surface-3)", margin: "60px 0 0", position: "relative" }}>
                {/* Progress fill */}
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: "100%" }}
                  transition={{ duration: 2, ease: "easeOut" }}
                  style={{ height: "100%", background: "linear-gradient(to right, var(--color-compromised), var(--color-risk), var(--color-safe))" }}
                />
              </div>
              
              {/* Events */}
              <div style={{ display: "flex", justifyContent: "space-between", position: "absolute", top: "0", left: "0", right: "0" }}>
                {TIMELINE_EVENTS.map((event, i) => (
                  <motion.div
                    key={event.id}
                    initial={{ opacity: 0, y: -20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.15 }}
                    style={{ display: "flex", flexDirection: "column", alignItems: "center", cursor: "pointer", flex: 1 }}
                    onClick={() => setSelectedEvent(selectedEvent?.id === event.id ? null : event)}
                  >
                    <div style={{ fontSize: "0.625rem", fontFamily: "var(--font-mono)", color: "var(--color-text-muted)", marginBottom: "0.5rem" }}>{event.time}</div>
                    <motion.div
                      whileHover={{ scale: 1.3 }}
                      style={{
                        width: "12px", height: "12px", borderRadius: "50%",
                        background: EVENT_COLOR[event.type],
                        border: `2px solid ${EVENT_COLOR[event.type]}`,
                        boxShadow: `0 0 8px ${EVENT_COLOR[event.type]}40`,
                        zIndex: 1, position: "relative",
                        ...(selectedEvent?.id === event.id ? { boxShadow: `0 0 16px ${EVENT_COLOR[event.type]}` } : {}),
                      }}
                    />
                    <div style={{ fontSize: "0.5625rem", textAlign: "center", marginTop: "8px", maxWidth: "80px", color: "var(--color-text-muted)", lineHeight: 1.3 }}>
                      {event.title.split(" ").slice(0, 3).join(" ")}
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
            
            {/* Selected Event Detail */}
            <AnimatePresence>
              {selectedEvent && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 10 }}
                  style={{ marginTop: "1.5rem", padding: "0.75rem 1rem", background: "var(--color-surface-2)", border: `1px solid ${EVENT_COLOR[selectedEvent.type]}30`, borderLeft: `3px solid ${EVENT_COLOR[selectedEvent.type]}`, display: "flex", gap: "2rem" }}
                >
                  <div>
                    <div style={{ fontSize: "0.6875rem", fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: EVENT_COLOR[selectedEvent.type], marginBottom: "0.25rem" }}>
                      {selectedEvent.time} UTC · {selectedEvent.type.toUpperCase()}
                    </div>
                    <div style={{ fontWeight: 600, color: "var(--color-text-primary)", marginBottom: "0.25rem", fontSize: "0.875rem" }}>{selectedEvent.title}</div>
                    <div style={{ fontSize: "0.8125rem", color: "var(--color-text-secondary)" }}>{selectedEvent.description}</div>
                  </div>
                  <div style={{ flexShrink: 0 }}>
                    <div style={{ fontSize: "0.6875rem", color: "var(--color-text-muted)" }}>Target Node</div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.8125rem", color: "var(--color-text-accent)" }}>{selectedEvent.node}</div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
}
