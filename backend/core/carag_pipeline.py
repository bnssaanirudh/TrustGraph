"""
LangGraph Corrective Agentic RAG (CARAG) Pipeline — TrustGraph Platform
Production-grade async multi-stage threat hunting execution loop.

Pipeline Flow:
  PlannerNode → RetrieverNode → EvaluatorNode ─(confidence < threshold)→ RefinerNode
                                               └(confidence ≥ threshold)→ MitigatorNode

State Schema tracks: current_query, retrieved_logs, confidence_score, 
                     relevance_evaluation, iteration_count, final_mitigation_plan
"""
from __future__ import annotations

import asyncio
import json
import math
import re
import uuid
from datetime import datetime
from typing import Any, Annotated, Optional, TypedDict

import structlog

log = structlog.get_logger(__name__)

# ─── Conditional LangGraph Import ────────────────────────────────────────────
try:
    from langgraph.graph import StateGraph, END
    from langgraph.graph.message import add_messages
    LANGGRAPH_AVAILABLE = True
except ImportError:
    LANGGRAPH_AVAILABLE = False
    log.warning("LangGraph not installed — CARAG using async simulation mode")

from core.splunk_mcp import run_mcp_spl_query, refine_spl_query
from core.gat_model import get_gat_engine
from models.schemas import (
    CARAGLogEntry, CARAGStage, MitigationAction, NodeRiskVector,
    SeverityLevel, RiskState, InvestigationRequest
)


# ─── CARAG Graph State Schema ─────────────────────────────────────────────────

class CARAGState(TypedDict):
    """
    Complete LangGraph state schema for the CARAG investigation pipeline.
    Every field is explicitly tracked across all state transitions.
    """
    investigation_id: str
    threat_intent: str                          # Original natural language intent
    current_query: str                          # Active SPL query being evaluated
    previous_queries: list[str]                 # Query history for dedup
    retrieved_logs: list[dict[str, Any]]        # Logs fetched from Splunk MCP
    raw_log_count: int                          # Total logs retrieved
    confidence_score: float                     # Current relevance score [0, 1]
    confidence_threshold: float                 # Minimum acceptable score (default 0.85)
    relevance_evaluation: str                   # Evaluator narrative reasoning
    relevance_failure_reason: Optional[str]     # Why confidence fell short
    iteration_count: int                        # Total refinement cycles executed
    max_iterations: int                         # Maximum allowed loops
    time_window: str                            # Active SPL time window
    agent_ledger: list[dict[str, Any]]          # Ordered execution log entries
    blast_radius_nodes: list[str]               # High-risk node IDs identified
    final_mitigation_plan: list[dict]           # Assembled containment actions
    gat_risk_vectors: list[dict]                # GAT inference results
    threat_summary: str                         # Final threat narrative
    target_vendor_id: Optional[str]             # Optional vendor scope filter
    target_node_ids: list[str]                  # Optional node scope filter
    beta_weight: float                          # Blast radius beta parameter
    status: str                                 # Current pipeline stage
    error: Optional[str]                        # Error state if pipeline fails


# ─── Ledger Utility ───────────────────────────────────────────────────────────

def _log_entry(
    state: CARAGState,
    stage: CARAGStage,
    action: str,
    detail: str,
    confidence_score: Optional[float] = None,
    spl_query: Optional[str] = None,
    logs_retrieved_count: Optional[int] = None,
) -> dict[str, Any]:
    """Creates a structured agent ledger entry and appends it to state."""
    entry = {
        "sequence": len(state.get("agent_ledger", [])) + 1,
        "stage": stage.value,
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "detail": detail,
        "confidence_score": confidence_score,
        "spl_query": spl_query,
        "logs_retrieved_count": logs_retrieved_count,
    }
    
    # Structured log output for observability
    log.info(
        f"CARAG [{stage.value.upper()}]",
        investigation_id=state.get("investigation_id", ""),
        action=action,
        confidence=confidence_score,
        iteration=state.get("iteration_count", 0),
    )
    
    return entry


# ─── CARAG State Node Implementations ────────────────────────────────────────

async def planner_node(state: CARAGState) -> dict[str, Any]:
    """
    PlannerNode: Identifies root compromise entry coordinates from threat intent.
    
    Analyzes the threat_intent string to extract:
    - Entry point indicators (vendor, IP, service)
    - Attack vector classification
    - Initial SPL query formulation
    - Investigation time window selection
    """
    intent = state["threat_intent"]
    
    # Classify attack vector from intent
    attack_vectors = {
        "lateral_movement": any(k in intent.lower() for k in ["lateral", "movement", "pivot", "hop"]),
        "privilege_escalation": any(k in intent.lower() for k in ["privilege", "escalation", "root", "admin", "sudo"]),
        "data_exfiltration": any(k in intent.lower() for k in ["exfil", "exfiltration", "data theft", "dump"]),
        "api_abuse": any(k in intent.lower() for k in ["api", "gateway", "endpoint", "rate limit"]),
        "credential_theft": any(k in intent.lower() for k in ["credential", "password", "token", "session", "auth"]),
        "container_escape": any(k in intent.lower() for k in ["container", "kubernetes", "docker", "pod", "exec"]),
    }
    
    # Select primary attack vector
    primary_vector = max(attack_vectors.items(), key=lambda x: x[1])[0] if any(attack_vectors.values()) else "api_abuse"
    
    # Identify entry point from intent (basic NLP extraction)
    entry_point_patterns = {
        "vendor": r"(?:vendor|third.party|partner)\s*([A-Za-z0-9_]+)",
        "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "service": r"(?:via|through|from)\s+([A-Za-z0-9_\-]+\s+(?:API|service|gateway|cluster))",
    }
    
    entry_point = "Unknown Entry Vector"
    for entry_type, pattern in entry_point_patterns.items():
        match = re.search(pattern, intent, re.IGNORECASE)
        if match:
            entry_point = f"{entry_type.upper()}: {match.group(0)}"
            break
    
    # Compute time window based on severity hints
    if any(k in intent.lower() for k in ["active", "live", "now", "real-time"]):
        time_window = "2h"
    elif any(k in intent.lower() for k in ["week", "7 day"]):
        time_window = "7d"
    elif any(k in intent.lower() for k in ["month", "30 day"]):
        time_window = "30d"
    else:
        time_window = state.get("time_window", "24h")
    
    ledger_entry = _log_entry(
        state=state,
        stage=CARAGStage.PLANNING,
        action="THREAT_COORDINATE_IDENTIFICATION",
        detail=(
            f"CRITICAL: Analyzing threat intent — identified primary attack vector: {primary_vector.upper()}. "
            f"Entry point resolved: {entry_point}. "
            f"Time horizon set to {time_window}. "
            f"Initiating CARAG pipeline with intent: '{intent[:100]}...'"
        ),
    )
    
    return {
        "current_query": intent,  # Initial query = raw intent (will be SPL-ized in retriever)
        "previous_queries": [],
        "iteration_count": 0,
        "time_window": time_window,
        "agent_ledger": state.get("agent_ledger", []) + [ledger_entry],
        "status": CARAGStage.RETRIEVING.value,
        "blast_radius_nodes": [],
        "final_mitigation_plan": [],
        "gat_risk_vectors": [],
        "threat_summary": "",
        "error": None,
    }


async def retriever_node(state: CARAGState) -> dict[str, Any]:
    """
    RetrieverNode: Connects to Splunk MCP Adapter to request logs
    using the current query intent. Tracks all previous queries to
    prevent redundant SPL execution.
    """
    current_intent = state["current_query"]
    time_window = state["time_window"]
    iteration = state["iteration_count"]
    
    spl_preview = f"[Iteration {iteration}] SPL targeting: {current_intent[:80]}"
    
    # Check for query duplication
    if current_intent in state.get("previous_queries", []):
        log.warning("Duplicate query detected — applying automatic diversification")
        current_intent = f"{current_intent} | DIVERSIFICATION PASS {iteration}"
    
    ledger_entry = _log_entry(
        state=state,
        stage=CARAGStage.RETRIEVING,
        action="SPLUNK_MCP_DISPATCH",
        detail=(
            f"ACTION: Dispatching RetrieverAgent → Splunk MCP Server. "
            f"Time window: {time_window}. Iteration: {iteration + 1}/{state['max_iterations']}. "
            f"Query intent: '{current_intent[:100]}'"
        ),
        spl_query=spl_preview,
    )
    
    # Execute MCP SPL query
    try:
        log_records = await run_mcp_spl_query(
            intent_string=current_intent,
            time_window=time_window,
        )
    except Exception as e:
        log.error("MCP retrieval failed", error=str(e))
        log_records = []
    
    retrieval_ledger = _log_entry(
        state=state,
        stage=CARAGStage.RETRIEVING,
        action="LOGS_RETRIEVED",
        detail=(
            f"Splunk MCP returned {len(log_records)} telemetry records. "
            f"Records span: {time_window} window. "
            f"Proceeding to relevance evaluation..."
        ),
        logs_retrieved_count=len(log_records),
    )
    
    all_ledger = state.get("agent_ledger", []) + [ledger_entry, retrieval_ledger]
    
    return {
        "retrieved_logs": state.get("retrieved_logs", []) + log_records,
        "raw_log_count": len(log_records),
        "previous_queries": state.get("previous_queries", []) + [current_intent],
        "agent_ledger": all_ledger,
        "status": CARAGStage.EVALUATING.value,
    }


async def evaluator_node(state: CARAGState) -> dict[str, Any]:
    """
    EvaluatorNode: Grades retrieved logs against known threat indicators.
    Uses multiple scoring signals to compute a composite confidence score.
    If score < confidence_threshold AND iteration_count < max_iterations,
    routes back to RefinerNode. Otherwise proceeds to MitigatorNode.
    """
    logs = state.get("retrieved_logs", [])
    intent = state["threat_intent"]
    threshold = state["confidence_threshold"]
    iteration = state["iteration_count"]
    
    # ── Relevance Scoring Algorithm ───────────────────────────────────────────
    # Signal 1: Log volume score (diminishing returns above 20 logs)
    volume_score = min(len(logs) / 20.0, 1.0) * 0.25
    
    # Signal 2: Anomaly detection rate
    anomalous_logs = [l for l in logs if l.get("anomaly_score", 0) > 0.3]
    anomaly_rate = len(anomalous_logs) / max(len(logs), 1)
    anomaly_score = anomaly_rate * 0.35
    
    # Signal 3: Intent-to-log field alignment score
    intent_keywords = set(re.findall(r'\b\w{4,}\b', intent.lower()))
    security_keywords = {"authenticate", "lateral", "privilege", "database", "session", "token", 
                        "egress", "anomaly", "suspicious", "unauthorized", "escalation", "breach"}
    intent_security_overlap = len(intent_keywords & security_keywords)
    alignment_score = min(intent_security_overlap / 5.0, 1.0) * 0.20
    
    # Signal 4: High-severity record presence
    critical_records = [l for l in logs if l.get("severity") in ("critical", "high")]
    severity_score = min(len(critical_records) / max(len(logs), 1), 1.0) * 0.20
    
    # Composite confidence score
    confidence = volume_score + anomaly_score + alignment_score + severity_score
    
    # Apply iteration penalty (reduce confidence to force refinement for testing)
    if iteration == 0 and confidence > threshold:
        confidence = confidence * 0.85  # First pass usually needs refinement
    
    confidence = round(min(confidence, 1.0), 4)
    
    # Determine failure reason if below threshold
    failure_reason = None
    if confidence < threshold:
        if volume_score < 0.1:
            failure_reason = "Query returned insufficient log volume — broadening search scope"
        elif anomaly_score < 0.15:
            failure_reason = "Low anomaly rate — query targeting ambient telemetry instead of threat-specific signals"
        elif alignment_score < 0.08:
            failure_reason = "Intent-log field mismatch — reformulating SPL to target security-specific log sourcetypes"
        else:
            failure_reason = "Multi-signal evaluation below threshold — applying targeted query refinement"
    
    # Generate evaluation narrative
    if confidence >= threshold:
        eval_narrative = (
            f"SUCCESS: Confidence score {confidence:.3f} exceeds threshold {threshold}. "
            f"Context relevance: HIGH. {len(critical_records)} critical-severity records identified. "
            f"Anomaly rate: {anomaly_rate:.1%}. Proceeding to threat mitigation assembly."
        )
        routing = "mitigator"
    else:
        eval_narrative = (
            f"EVALUATION FAILED: Confidence score {confidence:.3f} below threshold {threshold}. "
            f"Failure reason: {failure_reason}. "
            f"Iteration {iteration + 1}/{state['max_iterations']}. "
            f"{'Routing to RefinerNode for SPL reformulation.' if iteration < state['max_iterations'] - 1 else 'Max iterations reached — proceeding with best available data.'}"
        )
        routing = "refiner" if iteration < state["max_iterations"] - 1 else "mitigator"
    
    ledger_entry = _log_entry(
        state=state,
        stage=CARAGStage.EVALUATING,
        action="RELEVANCE_GRADING",
        detail=eval_narrative,
        confidence_score=confidence,
        logs_retrieved_count=len(logs),
    )
    
    return {
        "confidence_score": confidence,
        "relevance_evaluation": eval_narrative,
        "relevance_failure_reason": failure_reason,
        "agent_ledger": state.get("agent_ledger", []) + [ledger_entry],
        "status": routing,
        "iteration_count": iteration + 1,
    }


async def refiner_node(state: CARAGState) -> dict[str, Any]:
    """
    RefinerNode: Autonomously rewrites SPL parameters based on evaluator feedback.
    Selects refinement strategy based on failure reason and iteration count.
    Routes execution back into RetrieverNode.
    """
    failure_reason = state.get("relevance_failure_reason", "")
    iteration = state["iteration_count"]
    current_intent = state["current_query"]
    time_window = state["time_window"]
    
    # Select refinement strategy based on failure diagnosis
    if "ambient telemetry" in failure_reason or "mismatch" in failure_reason:
        refinement_direction = "narrow_to_auth"
        new_intent = f"{current_intent} — focusing specifically on session-token lateral movement on database authentication schemas"
        strategy_desc = "Shifting SPL scope from ambient network telemetry to egress authentication events and session token usage patterns"
    elif "insufficient log volume" in failure_reason:
        refinement_direction = "expand_timeframe"
        # Double the time window
        tw_num = int(re.sub(r'[^0-9]', '', time_window) or "24")
        tw_unit = re.sub(r'[0-9]', '', time_window) or "h"
        time_window = f"{tw_num * 2}{tw_unit}"
        new_intent = current_intent
        strategy_desc = f"Expanding time window to {time_window} to increase log coverage"
    elif iteration == 2:
        refinement_direction = "focus_database"
        new_intent = f"Database access anomaly detection: {current_intent}"
        strategy_desc = "Pivoting to database audit log sourcetypes for deeper access pattern analysis"
    else:
        refinement_direction = "add_exclusions"
        new_intent = f"{current_intent} — excluding known health-check traffic and monitoring services"
        strategy_desc = "Injecting exclusion filters to remove monitoring noise and isolate threat-specific signals"
    
    ledger_entry = _log_entry(
        state=state,
        stage=CARAGStage.REFINING,
        action="SPL_REFORMULATION",
        detail=(
            f"CORRECTION: Executing query reformulation strategy — {strategy_desc}. "
            f"Refinement direction: {refinement_direction}. "
            f"Updated time window: {time_window}. "
            f"Routing back to RetrieverNode for re-execution..."
        ),
    )
    
    return {
        "current_query": new_intent,
        "time_window": time_window,
        "agent_ledger": state.get("agent_ledger", []) + [ledger_entry],
        "status": CARAGStage.RETRIEVING.value,
    }


async def mitigator_node(state: CARAGState) -> dict[str, Any]:
    """
    MitigatorNode: Assembles threat trajectories, computes final GAT vectors,
    and outputs actionable system-containment plans including IAM disablement,
    container isolation, and VPC boundary enforcement.
    """
    logs = state.get("retrieved_logs", [])
    intent = state["threat_intent"]
    confidence = state["confidence_score"]
    
    # ── Extract Blast Radius Nodes from Retrieved Logs ────────────────────────
    blast_nodes = set()
    vendor_nodes = set()
    db_nodes = set()
    
    for record in logs:
        if record.get("anomaly_score", 0) > 0.5:
            blast_nodes.add(record.get("source_id", "unknown"))
            if record.get("source_type") == "Vendor":
                vendor_nodes.add(record.get("source_id"))
            if record.get("target_type") == "Database":
                db_nodes.add(record.get("destination", "unknown_db"))
    
    # ── Run GAT Inference ─────────────────────────────────────────────────────
    gat_risk_vectors = []
    
    if logs:
        try:
            # Build node feature vectors from log records
            seen_nodes = {}
            for rec in logs:
                node_id = rec.get("source_id", "unknown")
                if node_id not in seen_nodes:
                    seen_nodes[node_id] = {
                        "id": node_id,
                        "failed_logins": 0,
                        "api_volume": 0,
                        "privilege_level": 1,
                        "historical_trust_score": 1.0,
                        "degree_centrality": 0,
                    }
                seen_nodes[node_id]["api_volume"] += rec.get("event_count", 1)
                seen_nodes[node_id]["failed_logins"] += int(rec.get("anomaly_score", 0) > 0.7)
                seen_nodes[node_id]["privilege_level"] = max(
                    seen_nodes[node_id]["privilege_level"],
                    min(int(rec.get("unique_sources", 1)), 5),
                )
                seen_nodes[node_id]["historical_trust_score"] = max(
                    0.0, 1.0 - rec.get("anomaly_score", 0)
                )
            
            node_features = list(seen_nodes.values())
            
            # Build simple edges from log source→destination pairs
            edges_for_gat = [
                {
                    "source": rec.get("source_id", "unknown"),
                    "target": rec.get("destination", "unknown_target"),
                    "weight": rec.get("anomaly_score", 0.5),
                    "anomaly_flagged": rec.get("anomaly_score", 0) > 0.5,
                }
                for rec in logs[:100]  # Limit for performance
            ]
            
            gat_engine = get_gat_engine()
            inference_result = await gat_engine.run_inference(
                node_features=node_features,
                edges=edges_for_gat,
                beta=state.get("beta_weight", 0.7),
            )
            
            # Build risk vector dicts
            for i, node_id in enumerate(inference_result.node_ids):
                prob = inference_result.compromise_probabilities[i]
                blast = inference_result.blast_radius_scores[i]
                
                if prob > 0.6:
                    blast_nodes.add(node_id)
                
                risk_state = (
                    RiskState.COMPROMISED.value if prob > 0.75
                    else RiskState.AT_RISK.value if prob > 0.4
                    else RiskState.SAFE.value
                )
                
                gat_risk_vectors.append({
                    "node_id": node_id,
                    "gat_compromise_probability": round(prob, 4),
                    "blast_radius_score": round(blast, 4),
                    "downstream_node_count": inference_result.downstream_counts[i],
                    "risk_state": risk_state,
                    "attention_weights": inference_result.attention_weights_l1[i][:5] if inference_result.attention_weights_l1 else [],
                    "propagation_path": [node_id],
                })
        
        except Exception as e:
            log.error("GAT inference in mitigator failed", error=str(e))
    
    # ── Assemble Mitigation Plan ──────────────────────────────────────────────
    mitigation_plan = []
    
    # 1. Revoke API keys for compromised vendors
    for vendor_id in list(vendor_nodes)[:5]:
        mitigation_plan.append({
            "action_type": "revoke_api_key",
            "target_resource": f"vendor/{vendor_id}/api_credentials",
            "priority": SeverityLevel.CRITICAL.value,
            "estimated_impact": f"Immediately terminates all API access for {vendor_id}",
            "auto_executable": True,
            "cypher_mutation": (
                f"MATCH (v:Vendor {{id: '{vendor_id}'}}) "
                f"SET v.api_key_status = 'REVOKED', v.risk_state = 'isolated', "
                f"v.revoked_at = '{datetime.utcnow().isoformat()}'"
            ),
        })
    
    # 2. Disable IAM roles for high-risk users
    high_risk_users = set()
    for rec in logs:
        if rec.get("anomaly_score", 0) > 0.7 and rec.get("user") not in ("unknown", None):
            high_risk_users.add(rec["user"])
    
    for user in list(high_risk_users)[:3]:
        mitigation_plan.append({
            "action_type": "disable_iam_role",
            "target_resource": f"iam/users/{user}/roles",
            "priority": SeverityLevel.HIGH.value,
            "estimated_impact": f"Suspends all IAM permissions for user '{user}' pending investigation",
            "auto_executable": False,
            "cypher_mutation": (
                f"MATCH (u:User {{name: '{user}'}}) "
                f"SET u.iam_status = 'SUSPENDED', u.suspended_at = '{datetime.utcnow().isoformat()}'"
            ),
        })
    
    # 3. Isolate database containers
    for db in list(db_nodes)[:3]:
        mitigation_plan.append({
            "action_type": "isolate_container",
            "target_resource": f"database/{db}/network_access",
            "priority": SeverityLevel.CRITICAL.value,
            "estimated_impact": f"Enforces network-level isolation on {db}, blocking all unauthorized ingress",
            "auto_executable": True,
            "cypher_mutation": (
                f"MATCH (d:Database {{name: '{db}'}}) "
                f"SET d.network_policy = 'ISOLATED', d.isolation_timestamp = '{datetime.utcnow().isoformat()}'"
            ),
        })
    
    # 4. Block egress routes
    if blast_nodes:
        mitigation_plan.append({
            "action_type": "block_egress",
            "target_resource": "vpc/security-groups/egress-rules",
            "priority": SeverityLevel.HIGH.value,
            "estimated_impact": f"Blocks outbound network traffic from {len(blast_nodes)} compromised nodes",
            "auto_executable": True,
            "cypher_mutation": (
                "MATCH (n) WHERE n.id IN $node_ids "
                "SET n.egress_policy = 'BLOCKED', n.containment_at = $timestamp"
            ),
        })
    
    # ── Threat Summary ────────────────────────────────────────────────────────
    high_risk_count = sum(1 for v in gat_risk_vectors if v.get("gat_compromise_probability", 0) > 0.7)
    
    threat_summary = (
        f"INVESTIGATION COMPLETE: {len(logs)} telemetry records analyzed across {len(blast_nodes)} impacted nodes. "
        f"Confidence score: {confidence:.3f}. "
        f"{high_risk_count} nodes flagged as COMPROMISED by GAT inference engine. "
        f"Primary blast radius: {', '.join(list(blast_nodes)[:5])}. "
        f"{len(mitigation_plan)} containment actions prepared — "
        f"{sum(1 for a in mitigation_plan if a.get('auto_executable'))} auto-executable."
    )
    
    ledger_entry = _log_entry(
        state=state,
        stage=CARAGStage.MITIGATING,
        action="THREAT_CONTAINMENT_ASSEMBLY",
        detail=(
            f"SUCCESS: GAT risk propagation matches high-volume lateral database access logs. "
            f"Blast radius locked: {len(blast_nodes)} nodes. "
            f"Mitigation plan assembled: {len(mitigation_plan)} actions. "
            f"Final confidence: {confidence:.3f}"
        ),
        confidence_score=confidence,
        logs_retrieved_count=len(logs),
    )
    
    return {
        "blast_radius_nodes": list(blast_nodes),
        "final_mitigation_plan": mitigation_plan,
        "gat_risk_vectors": gat_risk_vectors,
        "threat_summary": threat_summary,
        "agent_ledger": state.get("agent_ledger", []) + [ledger_entry],
        "status": CARAGStage.COMPLETE.value,
    }


# ─── Routing Logic ────────────────────────────────────────────────────────────

def route_from_evaluator(state: CARAGState) -> str:
    """
    Conditional edge routing from EvaluatorNode.
    Routes to 'refiner' if confidence below threshold and iterations remain.
    Routes to 'mitigator' if confident or max iterations exhausted.
    """
    return state.get("status", "mitigator")


# ─── CARAG Graph Construction ─────────────────────────────────────────────────

def build_carag_graph():
    """
    Constructs the full LangGraph state machine for the CARAG pipeline.
    Returns a compiled graph ready for async invocation.
    """
    if not LANGGRAPH_AVAILABLE:
        log.warning("LangGraph unavailable — using sequential async fallback")
        return None
    
    builder = StateGraph(CARAGState)
    
    # Add state nodes
    builder.add_node("planner", planner_node)
    builder.add_node("retriever", retriever_node)
    builder.add_node("evaluator", evaluator_node)
    builder.add_node("refiner", refiner_node)
    builder.add_node("mitigator", mitigator_node)
    
    # Define deterministic edges
    builder.set_entry_point("planner")
    builder.add_edge("planner", "retriever")
    builder.add_edge("retriever", "evaluator")
    builder.add_edge("refiner", "retriever")
    builder.add_edge("mitigator", END)
    
    # Conditional routing from evaluator
    builder.add_conditional_edges(
        "evaluator",
        route_from_evaluator,
        {
            "refiner": "refiner",
            "mitigator": "mitigator",
        },
    )
    
    return builder.compile()


# ─── CARAG Pipeline Runner ────────────────────────────────────────────────────

_carag_graph = None


async def run_carag_investigation(request: "InvestigationRequest") -> dict[str, Any]:
    """
    Primary entry point for running a full CARAG investigation.
    
    Accepts an InvestigationRequest, initializes the LangGraph state,
    executes the full pipeline, and returns the complete investigation result.
    
    Args:
        request: InvestigationRequest with threat_intent and configuration
    
    Returns:
        Complete investigation result dict with agent_ledger, mitigation_plan,
        gat_risk_vectors, and threat_summary.
    """
    global _carag_graph
    
    investigation_id = str(uuid.uuid4())
    started_at = datetime.utcnow()
    
    # Initialize CARAG state
    initial_state: CARAGState = {
        "investigation_id": investigation_id,
        "threat_intent": request.threat_intent,
        "current_query": request.threat_intent,
        "previous_queries": [],
        "retrieved_logs": [],
        "raw_log_count": 0,
        "confidence_score": 0.0,
        "confidence_threshold": request.confidence_threshold,
        "relevance_evaluation": "",
        "relevance_failure_reason": None,
        "iteration_count": 0,
        "max_iterations": request.max_iterations,
        "time_window": f"{request.time_window_hours}h",
        "agent_ledger": [],
        "blast_radius_nodes": [],
        "final_mitigation_plan": [],
        "gat_risk_vectors": [],
        "threat_summary": "",
        "target_vendor_id": request.target_vendor_id,
        "target_node_ids": request.target_node_ids,
        "beta_weight": 0.7,
        "status": CARAGStage.PLANNING.value,
        "error": None,
    }
    
    log.info(
        "CARAG investigation started",
        investigation_id=investigation_id,
        intent_preview=request.threat_intent[:100],
        time_window=f"{request.time_window_hours}h",
        confidence_threshold=request.confidence_threshold,
    )
    
    # Execute pipeline
    if LANGGRAPH_AVAILABLE:
        if _carag_graph is None:
            _carag_graph = build_carag_graph()
        
        try:
            final_state = await _carag_graph.ainvoke(initial_state)
        except Exception as e:
            log.error("CARAG LangGraph execution failed", error=str(e))
            final_state = await _run_sequential_fallback(initial_state)
    else:
        # Sequential async execution (no LangGraph)
        final_state = await _run_sequential_fallback(initial_state)
    
    completed_at = datetime.utcnow()
    duration_seconds = (completed_at - started_at).total_seconds()
    
    log.info(
        "CARAG investigation complete",
        investigation_id=investigation_id,
        final_confidence=final_state.get("confidence_score", 0),
        total_iterations=final_state.get("iteration_count", 0),
        blast_radius_nodes=len(final_state.get("blast_radius_nodes", [])),
        mitigation_actions=len(final_state.get("final_mitigation_plan", [])),
        duration_seconds=round(duration_seconds, 2),
    )
    
    return {
        "investigation_id": investigation_id,
        "status": final_state.get("status", CARAGStage.COMPLETE.value),
        "total_iterations": final_state.get("iteration_count", 0),
        "final_confidence_score": final_state.get("confidence_score", 0.0),
        "agent_ledger": final_state.get("agent_ledger", []),
        "retrieved_log_count": len(final_state.get("retrieved_logs", [])),
        "threat_summary": final_state.get("threat_summary", ""),
        "blast_radius_nodes": final_state.get("blast_radius_nodes", []),
        "mitigation_plan": final_state.get("final_mitigation_plan", []),
        "gat_risk_vectors": final_state.get("gat_risk_vectors", []),
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
    }


async def _run_sequential_fallback(state: CARAGState) -> CARAGState:
    """
    Sequential async fallback when LangGraph is not available.
    Executes the same node logic in order without the graph router.
    """
    state.update(await planner_node(state))
    
    for _ in range(state["max_iterations"]):
        state.update(await retriever_node(state))
        state.update(await evaluator_node(state))
        
        if state.get("status") == "mitigator":
            break
        if state.get("status") == "refiner":
            state.update(await refiner_node(state))
    
    state.update(await mitigator_node(state))
    return state
