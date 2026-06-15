"use client";

import { useState, useCallback, useEffect } from "react";
import ReactFlow, {
  Node, Edge, Background, Controls, MiniMap,
  NodeTypes, Handle, Position, useNodesState, useEdgesState,
  MarkerType, Panel,
} from "reactflow";
import "reactflow/dist/style.css";
import { motion, AnimatePresence } from "framer-motion";

// ─── Node Type Definitions ────────────────────────────────────────────────────
interface NodeData {
  label: string; type: string; riskState: "safe" | "at_risk" | "compromised";
  ipAddress: string; serviceTier: string; iamPrivileges: string[];
  gatScore: number; anomalyCount: number; privilegeLevel: number;
}

// ─── Custom Risk Node Component ───────────────────────────────────────────────
function RiskNode({ data, selected }: { data: NodeData; selected: boolean }) {
  const stateConfig = {
    safe: { border: "var(--color-safe)", bg: "rgba(22,199,132,0.08)", glow: "rgba(22,199,132,0.3)", dot: "#16c784" },
    at_risk: { border: "var(--color-risk)", bg: "rgba(245,158,11,0.08)", glow: "rgba(245,158,11,0.3)", dot: "#f59e0b" },
    compromised: { border: "var(--color-compromised)", bg: "rgba(239,68,68,0.08)", glow: "rgba(239,68,68,0.4)", dot: "#ef4444" },
  };
  const cfg = stateConfig[data.riskState];
  const typeIcon: Record<string, string> = { Service: "⬡", Host: "◉", Container: "⬟", Database: "◈", User: "◆", Role: "◇" };

  return (
    <>
      <Handle type="target" position={Position.Top} style={{ background: cfg.border, width: 6, height: 6, border: "none" }} />
      <motion.div
        animate={data.riskState === "compromised" ? { boxShadow: [`0 0 0 0 ${cfg.glow}`, `0 0 16px 4px ${cfg.glow}`, `0 0 0 0 ${cfg.glow}`] } : {}}
        transition={{ duration: 2, repeat: Infinity }}
        style={{
          padding: "10px 14px", background: cfg.bg,
          border: `${data.riskState === "compromised" ? "2px" : "1px"} solid ${cfg.border}`,
          borderRadius: "4px", minWidth: "140px", maxWidth: "160px",
          outline: selected ? `2px solid ${cfg.border}` : "none",
          outlineOffset: "3px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
          <span style={{ fontSize: "14px", color: cfg.border }}>{typeIcon[data.type] || "○"}</span>
          <span style={{ fontSize: "9px", fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: cfg.border }}>
            {data.type}
          </span>
        </div>
        <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--color-text-primary)", lineHeight: 1.3, marginBottom: "6px" }}>
          {data.label}
        </div>
        <div style={{ fontSize: "9px", color: "var(--color-text-muted)", fontFamily: "var(--font-mono)" }}>
          GAT: <span style={{ color: cfg.border, fontWeight: 600 }}>{(data.gatScore * 100).toFixed(0)}%</span>
        </div>
      </motion.div>
      <Handle type="source" position={Position.Bottom} style={{ background: cfg.border, width: 6, height: 6, border: "none" }} />
    </>
  );
}

const nodeTypes: NodeTypes = { riskNode: RiskNode };

// ─── Graph Data ───────────────────────────────────────────────────────────────
const INITIAL_NODES: Node<NodeData>[] = [
  { id: "node_api_gw", type: "riskNode", position: { x: 300, y: 40 }, data: { label: "VendorX API Gateway", type: "Service", riskState: "compromised", ipAddress: "203.0.113.45", serviceTier: "external", iamPrivileges: ["api:invoke","logs:read"], gatScore: 0.89, anomalyCount: 47, privilegeLevel: 3 } },
  { id: "node_host_01", type: "riskNode", position: { x: 80, y: 180 }, data: { label: "web-prod-01", type: "Host", riskState: "compromised", ipAddress: "10.0.1.10", serviceTier: "dmz", iamPrivileges: ["ec2:describe"], gatScore: 0.74, anomalyCount: 21, privilegeLevel: 2 } },
  { id: "node_host_02", type: "riskNode", position: { x: 520, y: 180 }, data: { label: "app-prod-02", type: "Host", riskState: "at_risk", ipAddress: "10.0.1.11", serviceTier: "application", iamPrivileges: ["s3:read","ec2:describe"], gatScore: 0.55, anomalyCount: 8, privilegeLevel: 2 } },
  { id: "node_container_7", type: "riskNode", position: { x: 80, y: 340 }, data: { label: "svc-cluster-7", type: "Container", riskState: "at_risk", ipAddress: "172.16.7.7", serviceTier: "compute", iamPrivileges: ["k8s:exec","k8s:list"], gatScore: 0.68, anomalyCount: 15, privilegeLevel: 3 } },
  { id: "node_user_svc7", type: "riskNode", position: { x: 300, y: 340 }, data: { label: "svc_account_7", type: "User", riskState: "compromised", ipAddress: "10.0.1.45", serviceTier: "identity", iamPrivileges: ["iam:passrole","s3:*","rds:*"], gatScore: 0.77, anomalyCount: 28, privilegeLevel: 4 } },
  { id: "node_db_customer", type: "riskNode", position: { x: 80, y: 500 }, data: { label: "DB: customer_pii", type: "Database", riskState: "compromised", ipAddress: "10.0.2.50", serviceTier: "data", iamPrivileges: ["rds:read","rds:connect"], gatScore: 0.91, anomalyCount: 53, privilegeLevel: 4 } },
  { id: "node_db_prod01", type: "riskNode", position: { x: 520, y: 500 }, data: { label: "DB: prod-db-01", type: "Database", riskState: "compromised", ipAddress: "10.0.2.51", serviceTier: "data", iamPrivileges: ["rds:read","rds:write","rds:connect"], gatScore: 0.82, anomalyCount: 34, privilegeLevel: 4 } },
  { id: "node_role_dbreader", type: "riskNode", position: { x: 300, y: 500 }, data: { label: "Role: db_reader", type: "Role", riskState: "at_risk", ipAddress: "N/A", serviceTier: "identity", iamPrivileges: ["rds:select","rds:describe"], gatScore: 0.61, anomalyCount: 12, privilegeLevel: 3 } },
  { id: "node_api_paystream", type: "riskNode", position: { x: 760, y: 40 }, data: { label: "PayStream API", type: "Service", riskState: "at_risk", ipAddress: "198.51.100.55", serviceTier: "external", iamPrivileges: ["api:invoke"], gatScore: 0.42, anomalyCount: 7, privilegeLevel: 2 } },
  { id: "node_host_04", type: "riskNode", position: { x: 760, y: 180 }, data: { label: "pay-proxy-01", type: "Host", riskState: "safe", ipAddress: "10.0.1.22", serviceTier: "dmz", iamPrivileges: ["ec2:describe"], gatScore: 0.28, anomalyCount: 3, privilegeLevel: 1 } },
];

const ANOMALY_COLOR = "rgba(239,68,68,0.8)";
const NORMAL_COLOR = "rgba(72,80,92,0.6)";

const INITIAL_EDGES: Edge[] = [
  { id: "e1", source: "node_api_gw", target: "node_host_01", label: "CALLS", animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: ANOMALY_COLOR }, style: { stroke: ANOMALY_COLOR, strokeWidth: 2 }, labelStyle: { fill: "#ef4444", fontSize: 9, fontWeight: 700 } },
  { id: "e2", source: "node_host_01", target: "node_container_7", label: "DEPLOYS", animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: ANOMALY_COLOR }, style: { stroke: ANOMALY_COLOR, strokeWidth: 2 }, labelStyle: { fill: "#ef4444", fontSize: 9, fontWeight: 700 } },
  { id: "e3", source: "node_container_7", target: "node_user_svc7", label: "AUTHENTICATES", animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: ANOMALY_COLOR }, style: { stroke: ANOMALY_COLOR, strokeWidth: 2 }, labelStyle: { fill: "#ef4444", fontSize: 9, fontWeight: 700 } },
  { id: "e4", source: "node_user_svc7", target: "node_db_customer", label: "ACCESSES", animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: ANOMALY_COLOR }, style: { stroke: ANOMALY_COLOR, strokeWidth: 2.5 }, labelStyle: { fill: "#ef4444", fontSize: 9, fontWeight: 700 } },
  { id: "e5", source: "node_user_svc7", target: "node_db_prod01", label: "ACCESSES", animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: ANOMALY_COLOR }, style: { stroke: ANOMALY_COLOR, strokeWidth: 2 }, labelStyle: { fill: "#ef4444", fontSize: 9, fontWeight: 700 } },
  { id: "e6", source: "node_host_02", target: "node_container_7", label: "CONNECTS", animated: false, markerEnd: { type: MarkerType.ArrowClosed, color: NORMAL_COLOR }, style: { stroke: NORMAL_COLOR, strokeWidth: 1 }, labelStyle: { fill: "#484f58", fontSize: 9 } },
  { id: "e7", source: "node_role_dbreader", target: "node_db_customer", label: "ACCESSES", animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: ANOMALY_COLOR }, style: { stroke: ANOMALY_COLOR, strokeWidth: 1.5 }, labelStyle: { fill: "#ef4444", fontSize: 9, fontWeight: 700 } },
  { id: "e8", source: "node_api_gw", target: "node_host_02", label: "CALLS", animated: false, markerEnd: { type: MarkerType.ArrowClosed, color: NORMAL_COLOR }, style: { stroke: NORMAL_COLOR, strokeWidth: 1 }, labelStyle: { fill: "#484f58", fontSize: 9 } },
  { id: "e9", source: "node_api_paystream", target: "node_host_04", label: "CALLS", animated: false, markerEnd: { type: MarkerType.ArrowClosed, color: NORMAL_COLOR }, style: { stroke: NORMAL_COLOR, strokeWidth: 1 }, labelStyle: { fill: "#484f58", fontSize: 9 } },
  { id: "e10", source: "node_host_04", target: "node_db_customer", label: "CONNECTS", animated: false, markerEnd: { type: MarkerType.ArrowClosed, color: NORMAL_COLOR }, style: { stroke: NORMAL_COLOR, strokeWidth: 1 }, labelStyle: { fill: "#484f58", fontSize: 9 } },
];

// ─── Node Detail Panel ────────────────────────────────────────────────────────
function NodeDetailPanel({ node, onClose }: { node: Node<NodeData>; onClose: () => void }) {
  const d = node.data;
  const scoreColor = d.gatScore > 0.7 ? "var(--color-compromised)" : d.gatScore > 0.4 ? "var(--color-risk)" : "var(--color-safe)";

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      style={{ position: "absolute", top: "80px", right: "16px", width: "280px", background: "var(--color-surface-1)", border: "1px solid var(--color-border)", zIndex: 100, boxShadow: "0 8px 32px rgba(0,0,0,0.4)" }}
    >
      <div style={{ padding: "0.875rem 1rem", borderBottom: "1px solid var(--color-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: "0.8125rem", fontWeight: 600, color: "var(--color-text-primary)" }}>Node Inspector</span>
        <button onClick={onClose} style={{ background: "none", border: "none", color: "var(--color-text-muted)", cursor: "pointer", fontSize: "1.125rem", lineHeight: 1 }}>×</button>
      </div>
      
      <div style={{ padding: "1rem" }}>
        <div style={{ marginBottom: "1rem", paddingBottom: "1rem", borderBottom: "1px solid var(--color-border)" }}>
          <div style={{ fontSize: "0.6875rem", color: "var(--color-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "0.25rem" }}>{d.type}</div>
          <div style={{ fontSize: "1rem", fontWeight: 600, color: "var(--color-text-primary)" }}>{d.label}</div>
          <span className={`risk-badge ${d.riskState}`} style={{ marginTop: "0.5rem", display: "inline-flex" }}>
            <span className={`risk-dot ${d.riskState}`} />
            {d.riskState.replace("_", " ")}
          </span>
        </div>
        
        {[
          { label: "IP Address", value: d.ipAddress, mono: true },
          { label: "Service Tier", value: d.serviceTier },
          { label: "Anomaly Count", value: String(d.anomalyCount), color: d.anomalyCount > 20 ? "var(--color-compromised)" : undefined },
          { label: "Privilege Level", value: `${d.privilegeLevel} / 5` },
        ].map(({ label, value, mono, color }) => (
          <div key={label} style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.625rem" }}>
            <span style={{ fontSize: "0.6875rem", color: "var(--color-text-muted)", textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</span>
            <span style={{ fontSize: "0.8125rem", color: color || "var(--color-text-secondary)", fontFamily: mono ? "var(--font-mono)" : undefined }}>{value}</span>
          </div>
        ))}
        
        {/* GAT Score */}
        <div style={{ marginTop: "1rem", paddingTop: "1rem", borderTop: "1px solid var(--color-border)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.5rem" }}>
            <span style={{ fontSize: "0.6875rem", color: "var(--color-text-muted)", textTransform: "uppercase", letterSpacing: "0.06em" }}>GAT Compromise Score</span>
            <span style={{ fontSize: "0.875rem", fontWeight: 700, color: scoreColor, fontFamily: "var(--font-mono)" }}>{(d.gatScore * 100).toFixed(1)}%</span>
          </div>
          <div style={{ height: "6px", background: "var(--color-surface-3)", borderRadius: "3px", overflow: "hidden" }}>
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${d.gatScore * 100}%` }}
              transition={{ duration: 0.8, ease: "easeOut" }}
              style={{ height: "100%", background: scoreColor, borderRadius: "3px" }}
            />
          </div>
        </div>

        {/* IAM Privileges */}
        <div style={{ marginTop: "1rem", paddingTop: "1rem", borderTop: "1px solid var(--color-border)" }}>
          <div style={{ fontSize: "0.6875rem", color: "var(--color-text-muted)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "0.5rem" }}>IAM Privileges</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.375rem" }}>
            {d.iamPrivileges.map(priv => (
              <span key={priv} style={{ padding: "0.2rem 0.5rem", background: "var(--color-surface-3)", color: "var(--color-text-accent)", fontSize: "0.625rem", fontFamily: "var(--font-mono)", borderRadius: "2px" }}>
                {priv}
              </span>
            ))}
          </div>
        </div>
      </div>
    </motion.div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function GraphPage() {
  const [nodes, setNodes, onNodesChange] = useNodesState(INITIAL_NODES);
  const [edges, setEdges, onEdgesChange] = useEdgesState(INITIAL_EDGES);
  const [selectedNode, setSelectedNode] = useState<Node<NodeData> | null>(null);
  const [filter, setFilter] = useState<"all" | "compromised" | "at_risk" | "safe">("all");

  const onNodeClick = useCallback((_: any, node: Node) => {
    setSelectedNode(node as Node<NodeData>);
  }, []);

  useEffect(() => {
    const fetchGraphData = async () => {
      try {
        const res = await fetch("http://localhost:8001/api/graph");
        if (!res.ok) return;
        const data = await res.json();
        
        const mappedNodes: Node<NodeData>[] = data.nodes.map((n: any) => ({
          id: n.id,
          type: "riskNode",
          position: { x: n.position_x, y: n.position_y },
          data: {
            label: n.label,
            type: n.type,
            riskState: n.risk_state,
            ipAddress: n.ip_address,
            serviceTier: n.service_tier,
            iamPrivileges: n.iam_privileges || [],
            gatScore: n.gat_compromise_score,
            anomalyCount: n.anomaly_count,
            privilegeLevel: n.privilege_level
          }
        }));
        
        const mappedEdges: Edge[] = data.edges.map((e: any) => ({
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.relationship,
          animated: e.anomaly_flagged,
          markerEnd: { 
            type: MarkerType.ArrowClosed, 
            color: e.anomaly_flagged ? ANOMALY_COLOR : NORMAL_COLOR 
          },
          style: { 
            stroke: e.anomaly_flagged ? ANOMALY_COLOR : NORMAL_COLOR, 
            strokeWidth: e.anomaly_flagged ? Math.max(2, e.weight * 3) : 1 
          },
          labelStyle: { 
            fill: e.anomaly_flagged ? "#ef4444" : "#484f58", 
            fontSize: 9, 
            fontWeight: e.anomaly_flagged ? 700 : 400 
          }
        }));
        
        setNodes(mappedNodes);
        setEdges(mappedEdges);
      } catch (err) {
        console.error("Failed to fetch live graph:", err);
      }
    };
    
    // Initial fetch
    fetchGraphData();
    
    // Poll every 3 seconds
    const interval = setInterval(fetchGraphData, 3000);
    return () => clearInterval(interval);
  }, [setNodes, setEdges]);

  const visibleNodes = filter === "all" ? nodes : nodes.filter(n => n.data.riskState === filter);
  const visibleEdges = filter === "all" ? edges : edges.filter(e => 
    visibleNodes.some(n => n.id === e.source) && visibleNodes.some(n => n.id === e.target)
  );

  return (
    <div style={{ height: "100vh", display: "flex", flexDirection: "column" }}>
      <div className="console-header" style={{ flexShrink: 0 }}>
        <div>
          <div style={{ fontSize: "1.125rem", fontWeight: 600, color: "var(--color-text-primary)" }}>Interactive Graph Topology</div>
          <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: "2px" }}>Enterprise security graph · {nodes.length} nodes · {edges.length} edges</div>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          {(["all", "compromised", "at_risk", "safe"] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              style={{
                padding: "0.375rem 0.875rem", border: "1px solid var(--color-border)", background: filter === f ? "var(--color-surface-3)" : "transparent",
                color: filter === f ? "var(--color-text-primary)" : "var(--color-text-muted)",
                fontSize: "0.6875rem", fontWeight: 600, letterSpacing: "0.06em", textTransform: "uppercase", cursor: "pointer", transition: "all 0.15s",
              }}
            >
              {f.replace("_", " ")}
            </button>
          ))}
        </div>
      </div>
      
      <div style={{ flex: 1, position: "relative", background: "var(--color-surface-0)" }}>
        <ReactFlow
          nodes={visibleNodes}
          edges={visibleEdges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          style={{ background: "var(--color-surface-0)" }}
        >
          <Background color="var(--color-border)" gap={24} size={1} />
          <Controls style={{ background: "var(--color-surface-1)", border: "1px solid var(--color-border)" }} />
          <MiniMap
            nodeColor={(n) => {
              const d = (n as Node<NodeData>).data;
              return d?.riskState === "compromised" ? "#ef4444" : d?.riskState === "at_risk" ? "#f59e0b" : "#16c784";
            }}
            style={{ background: "var(--color-surface-1)", border: "1px solid var(--color-border)" }}
          />
          <Panel position="top-left">
            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem", background: "var(--color-surface-1)", border: "1px solid var(--color-border)", padding: "0.75rem" }}>
              {[["Compromised", "var(--color-compromised)", "compromised"], ["At Risk", "var(--color-risk)", "at_risk"], ["Safe", "var(--color-safe)", "safe"]].map(([label, color, state]) => (
                <div key={state} style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <span className={`risk-dot ${state}`} style={{ width: "8px", height: "8px" }} />
                  <span style={{ fontSize: "0.6875rem", color: "var(--color-text-secondary)" }}>{label}: {nodes.filter(n => n.data.riskState === state).length}</span>
                </div>
              ))}
              <div style={{ borderTop: "1px solid var(--color-border)", paddingTop: "0.5rem", marginTop: "0.25rem" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <div style={{ width: "16px", height: "2px", background: ANOMALY_COLOR }} />
                  <span style={{ fontSize: "0.6875rem", color: "var(--color-text-secondary)" }}>Anomalous Edge</span>
                </div>
              </div>
            </div>
          </Panel>
        </ReactFlow>
        
        <AnimatePresence>
          {selectedNode && (
            <NodeDetailPanel node={selectedNode} onClose={() => setSelectedNode(null)} />
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
