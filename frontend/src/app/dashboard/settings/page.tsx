"use client";

import { useState } from "react";
import { motion } from "framer-motion";

type SettingSection = "backend" | "gat" | "carag" | "splunk" | "neo4j";

interface SettingField {
  key: string; label: string; value: string; type: "text" | "number" | "password" | "select";
  description?: string; options?: string[]; critical?: boolean;
}

const CONFIG_SECTIONS: Record<SettingSection, { title: string; description: string; fields: SettingField[] }> = {
  backend: {
    title: "Backend API Configuration",
    description: "FastAPI server connection and authentication settings.",
    fields: [
      { key: "api_url", label: "API Base URL", value: "http://localhost:8000", type: "text", description: "FastAPI server endpoint" },
      { key: "api_key", label: "API Key", value: "trustgraph_dev_key_xxxx", type: "password", description: "Backend authentication token" },
      { key: "timeout_ms", label: "Request Timeout (ms)", value: "30000", type: "number", description: "HTTP request timeout" },
    ],
  },
  gat: {
    title: "GAT Engine Parameters",
    description: "PyTorch Geometric Graph Attention Network runtime configuration.",
    fields: [
      { key: "gat_beta", label: "Blast Radius β Weight", value: "0.7", type: "number", description: "Risk(N) = β·ΣAnomalySeverity + (1-β)·log(Downstream). Higher β = more local-anomaly sensitivity." },
      { key: "gat_hidden_dim", label: "Hidden Dimensions", value: "512", type: "number", description: "Internal node embedding size per GATConv layer." },
      { key: "gat_heads_l1", label: "Layer 1 Attention Heads", value: "8", type: "number", description: "Multi-head attention — layer 1." },
      { key: "gat_heads_l2", label: "Layer 2 Attention Heads", value: "4", type: "number", description: "Multi-head attention — layer 2 (output)." },
      { key: "gat_dropout", label: "Dropout Rate", value: "0.1", type: "number", description: "Training regularization dropout." },
      { key: "compromise_threshold", label: "Compromise Threshold", value: "0.75", type: "number", description: "GAT probability above which a node is classified as COMPROMISED.", critical: true },
    ],
  },
  carag: {
    title: "CARAG Pipeline Settings",
    description: "LangGraph Corrective Agentic RAG behavior configuration.",
    fields: [
      { key: "confidence_threshold", label: "Confidence Threshold", value: "0.85", type: "number", description: "Minimum relevance score before routing to mitigator. Below this, pipeline loops back to refiner.", critical: true },
      { key: "max_iterations", label: "Max Correction Iterations", value: "4", type: "number", description: "Maximum CARAG refinement loops before forced exit." },
      { key: "llm_model", label: "LLM Model", value: "gemini-2.5-flash-preview", type: "select", options: ["gemini-2.5-flash-preview", "gemini-2.5-pro-preview", "gpt-4o", "claude-3.5-sonnet"], description: "Language model for PlannerNode SPL generation." },
      { key: "embedding_model", label: "Embedding Model", value: "text-embedding-3-small", type: "select", options: ["text-embedding-3-small", "text-embedding-3-large"], description: "Retriever embedding model." },
      { key: "temperature", label: "LLM Temperature", value: "0.1", type: "number", description: "Generation temperature. Keep low (≤0.2) for deterministic query generation." },
    ],
  },
  splunk: {
    title: "Splunk MCP Integration",
    description: "Splunk Enterprise MCP server connection and query settings.",
    fields: [
      { key: "splunk_host", label: "Splunk Host", value: "localhost", type: "text" },
      { key: "splunk_port", label: "Splunk MCP Port", value: "8089", type: "number" },
      { key: "splunk_token", label: "Splunk HEC Token", value: "••••••••••••••••", type: "password", description: "HTTP Event Collector token for log ingestion.", critical: true },
      { key: "default_index", label: "Default Index", value: "trustgraph_security", type: "text" },
      { key: "time_window_hours", label: "Default Time Window (hours)", value: "24", type: "number" },
    ],
  },
  neo4j: {
    title: "Neo4j Graph Database",
    description: "Neo4j Enterprise connection and graph configuration.",
    fields: [
      { key: "neo4j_uri", label: "Neo4j URI", value: "bolt://localhost:7687", type: "text" },
      { key: "neo4j_user", label: "Username", value: "neo4j", type: "text" },
      { key: "neo4j_password", label: "Password", value: "••••••••••••", type: "password", critical: true },
      { key: "neo4j_database", label: "Database Name", value: "trustgraph", type: "text" },
      { key: "max_connection_pool", label: "Max Connection Pool", value: "50", type: "number" },
    ],
  },
};

const SECTION_KEYS: SettingSection[] = ["backend", "gat", "carag", "splunk", "neo4j"];

export default function SettingsPage() {
  const [activeSection, setActiveSection] = useState<SettingSection>("gat");
  const [editedValues, setEditedValues] = useState<Record<string, string>>({});
  const [saved, setSaved] = useState(false);

  const section = CONFIG_SECTIONS[activeSection];

  const getValue = (field: SettingField) => editedValues[field.key] ?? field.value;
  const setValue = (key: string, val: string) => setEditedValues(prev => ({ ...prev, [key]: val }));

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
    setEditedValues({});
  };

  const handleReset = () => setEditedValues({});

  return (
    <div style={{ height: "100vh", display: "flex", flexDirection: "column" }}>
      <div className="console-header" style={{ flexShrink: 0 }}>
        <div>
          <div style={{ fontSize: "1.125rem", fontWeight: 600, color: "var(--color-text-primary)" }}>Settings & Configuration</div>
          <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: "2px" }}>Runtime parameters for all TrustGraph engine components</div>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button onClick={handleReset} style={{ padding: "0.5rem 1rem", border: "1px solid var(--color-border)", background: "transparent", color: "var(--color-text-muted)", fontSize: "0.8125rem", cursor: "pointer" }}>
            Reset
          </button>
          <motion.button
            onClick={handleSave}
            animate={saved ? { background: "#16c784" } : { background: "var(--color-accent-red)" }}
            style={{ padding: "0.5rem 1.25rem", border: "none", color: "#fff", fontSize: "0.8125rem", fontWeight: 600, cursor: "pointer" }}
          >
            {saved ? "✓ Saved" : "Save Configuration"}
          </motion.button>
        </div>
      </div>

      <div style={{ flex: 1, display: "grid", gridTemplateColumns: "220px 1fr", overflow: "hidden" }}>
        {/* Left nav */}
        <div style={{ borderRight: "1px solid var(--color-border)", background: "var(--color-surface-1)", padding: "1.5rem 0" }}>
          <div className="section-label" style={{ padding: "0 1.25rem 0.75rem", color: "var(--color-text-muted)", fontSize: "0.5625rem" }}>COMPONENTS</div>
          {SECTION_KEYS.map(key => (
            <button
              key={key}
              onClick={() => setActiveSection(key)}
              style={{
                display: "flex", alignItems: "center", gap: "0.75rem", width: "100%",
                padding: "0.625rem 1.25rem", background: "none", border: "none",
                borderLeft: `2px solid ${activeSection === key ? "var(--color-accent-red)" : "transparent"}`,
                color: activeSection === key ? "var(--color-text-primary)" : "var(--color-text-muted)",
                background: activeSection === key ? "var(--color-surface-2)" : "transparent",
                fontSize: "0.8125rem", fontWeight: activeSection === key ? 600 : 400, cursor: "pointer",
                textAlign: "left", transition: "all 0.15s",
              }}
            >
              {CONFIG_SECTIONS[key].title.split(" ")[0]}
            </button>
          ))}
        </div>

        {/* Content */}
        <div style={{ overflowY: "auto", padding: "2rem" }}>
          <motion.div
            key={activeSection}
            initial={{ opacity: 0, x: 10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.2 }}
          >
            <h2 style={{ fontSize: "1.125rem", fontWeight: 700, color: "var(--color-text-primary)", marginBottom: "0.375rem" }}>{section.title}</h2>
            <p style={{ fontSize: "0.8125rem", color: "var(--color-text-muted)", marginBottom: "2rem" }}>{section.description}</p>

            <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
              {section.fields.map(field => {
                const currentValue = getValue(field);
                const isDirty = editedValues[field.key] !== undefined;

                return (
                  <div key={field.key} style={{ display: "grid", gridTemplateColumns: "280px 1fr", gap: "2rem", alignItems: "start", padding: "1.25rem", background: "var(--color-surface-1)", border: `1px solid ${isDirty ? "rgba(88,166,255,0.3)" : "var(--color-border)"}`, position: "relative" }}>
                    {field.critical && (
                      <div style={{ position: "absolute", top: "0.75rem", right: "0.75rem", padding: "0.2rem 0.5rem", background: "rgba(239,68,68,0.1)", color: "var(--color-compromised)", fontSize: "0.5625rem", fontWeight: 700, letterSpacing: "0.08em" }}>CRITICAL</div>
                    )}
                    <div>
                      <div style={{ fontSize: "0.875rem", fontWeight: 600, color: "var(--color-text-primary)", marginBottom: "0.25rem" }}>{field.label}</div>
                      {field.description && (
                        <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", lineHeight: 1.5 }}>{field.description}</div>
                      )}
                    </div>
                    <div>
                      {field.type === "select" ? (
                        <select
                          value={currentValue}
                          onChange={e => setValue(field.key, e.target.value)}
                          style={{ width: "100%", padding: "0.5rem 0.75rem", background: "var(--color-surface-2)", border: "1px solid var(--color-border)", color: "var(--color-text-primary)", fontSize: "0.875rem", fontFamily: "var(--font-mono)", cursor: "pointer" }}
                        >
                          {field.options?.map(o => <option key={o} value={o}>{o}</option>)}
                        </select>
                      ) : (
                        <input
                          type={field.type === "password" ? "password" : "text"}
                          value={currentValue}
                          onChange={e => setValue(field.key, e.target.value)}
                          style={{ width: "100%", padding: "0.5rem 0.75rem", background: "var(--color-surface-2)", border: "1px solid var(--color-border)", color: "var(--color-text-primary)", fontSize: "0.875rem", fontFamily: "var(--font-mono)", outline: "none" }}
                        />
                      )}
                      {isDirty && <div style={{ fontSize: "0.6875rem", color: "var(--color-text-accent)", marginTop: "0.25rem" }}>● Modified</div>}
                    </div>
                  </div>
                );
              })}
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  );
}
