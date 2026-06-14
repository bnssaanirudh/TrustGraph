"""FastAPI Router — CARAG Investigation (/api/investigate)"""
from __future__ import annotations
from datetime import datetime
from fastapi import APIRouter, HTTPException
import structlog
from models.schemas import (InvestigationRequest, InvestigationResponse, CARAGLogEntry, CARAGStage, MitigationAction, NodeRiskVector, RiskState, SeverityLevel)
from core.carag_pipeline import run_carag_investigation

router = APIRouter()
log = structlog.get_logger(__name__)

@router.post("/investigate", response_model=InvestigationResponse)
async def run_investigation(request: InvestigationRequest) -> InvestigationResponse:
    """Initialize LangGraph CARAG agent to execute iterative threat hunting loops."""
    try:
        result = await run_carag_investigation(request)
        ledger=[CARAGLogEntry(sequence=e["sequence"],stage=CARAGStage(e["stage"]),timestamp=datetime.fromisoformat(e["timestamp"]),action=e["action"],detail=e["detail"],confidence_score=e.get("confidence_score"),spl_query=e.get("spl_query"),logs_retrieved_count=e.get("logs_retrieved_count")) for e in result.get("agent_ledger",[])]
        mitigations=[MitigationAction(action_type=m["action_type"],target_resource=m["target_resource"],priority=SeverityLevel(m["priority"]),estimated_impact=m["estimated_impact"],auto_executable=m["auto_executable"],cypher_mutation=m.get("cypher_mutation")) for m in result.get("mitigation_plan",[])]
        gat_vectors=[NodeRiskVector(node_id=v["node_id"],gat_compromise_probability=v["gat_compromise_probability"],blast_radius_score=v["blast_radius_score"],downstream_node_count=v["downstream_node_count"],risk_state=RiskState(v["risk_state"]),attention_weights=v.get("attention_weights",[]),propagation_path=v.get("propagation_path",[v["node_id"]])) for v in result.get("gat_risk_vectors",[])]
        return InvestigationResponse(investigation_id=result["investigation_id"],status=CARAGStage(result["status"]),total_iterations=result["total_iterations"],final_confidence_score=result["final_confidence_score"],agent_ledger=ledger,retrieved_log_count=result["retrieved_log_count"],threat_summary=result["threat_summary"],blast_radius_nodes=result["blast_radius_nodes"],mitigation_plan=mitigations,gat_risk_vectors=gat_vectors,started_at=datetime.fromisoformat(result["started_at"]),completed_at=datetime.fromisoformat(result["completed_at"]) if result.get("completed_at") else None)
    except Exception as e:
        log.error("Investigation failed",error=str(e),exc_info=e)
        raise HTTPException(status_code=500,detail=f"CARAG pipeline error: {str(e)}")
