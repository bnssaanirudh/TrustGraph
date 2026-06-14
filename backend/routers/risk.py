"""FastAPI Router — Risk Inference (/api/risk)"""
from __future__ import annotations
import math
from fastapi import APIRouter, HTTPException
import structlog
from models.schemas import RiskInferenceRequest, RiskInferenceResponse, NodeRiskVector, RiskState
from core.gat_model import get_gat_engine

router = APIRouter()
log = structlog.get_logger(__name__)

GRAPH_NODES_DATA = [
    {"id":"node_api_gw","anomaly_count":47,"privilege_level":3,"historical_trust_score":0.11},
    {"id":"node_host_01","anomaly_count":21,"privilege_level":2,"historical_trust_score":0.28},
    {"id":"node_host_02","anomaly_count":8,"privilege_level":2,"historical_trust_score":0.52},
    {"id":"node_container_7","anomaly_count":15,"privilege_level":3,"historical_trust_score":0.35},
    {"id":"node_db_customer","anomaly_count":53,"privilege_level":4,"historical_trust_score":0.09},
    {"id":"node_db_prod01","anomaly_count":34,"privilege_level":4,"historical_trust_score":0.18},
    {"id":"node_user_svc7","anomaly_count":28,"privilege_level":4,"historical_trust_score":0.23},
    {"id":"node_role_dbreader","anomaly_count":12,"privilege_level":3,"historical_trust_score":0.40},
    {"id":"node_api_paystream","anomaly_count":7,"privilege_level":2,"historical_trust_score":0.61},
    {"id":"node_host_04","anomaly_count":3,"privilege_level":1,"historical_trust_score":0.75},
]
GRAPH_EDGES_DATA = [
    {"source":"node_api_gw","target":"node_host_01","weight":0.89,"anomaly_flagged":True},
    {"source":"node_host_01","target":"node_container_7","weight":0.74,"anomaly_flagged":True},
    {"source":"node_container_7","target":"node_user_svc7","weight":0.68,"anomaly_flagged":True},
    {"source":"node_user_svc7","target":"node_db_customer","weight":0.91,"anomaly_flagged":True},
    {"source":"node_user_svc7","target":"node_db_prod01","weight":0.82,"anomaly_flagged":True},
    {"source":"node_host_02","target":"node_container_7","weight":0.55,"anomaly_flagged":False},
    {"source":"node_role_dbreader","target":"node_db_customer","weight":0.61,"anomaly_flagged":True},
    {"source":"node_api_gw","target":"node_host_02","weight":0.45,"anomaly_flagged":False},
    {"source":"node_api_paystream","target":"node_host_04","weight":0.42,"anomaly_flagged":False},
    {"source":"node_host_04","target":"node_db_customer","weight":0.28,"anomaly_flagged":False},
]

@router.post("/risk", response_model=RiskInferenceResponse)
async def run_risk_inference(request: RiskInferenceRequest) -> RiskInferenceResponse:
    node_map = {n["id"]: n for n in GRAPH_NODES_DATA}
    node_ids_to_use = request.node_ids if request.node_ids else [n["id"] for n in GRAPH_NODES_DATA]
    
    node_features = []
    for nid in node_ids_to_use:
        node = node_map.get(nid)
        if node:
            degree = sum(1 for e in GRAPH_EDGES_DATA if e["source"]==nid or e["target"]==nid)
            node_features.append({"id":nid,"failed_logins":node["anomaly_count"]*2,"api_volume":node["anomaly_count"]*100,"privilege_level":node["privilege_level"],"historical_trust_score":node["historical_trust_score"],"degree_centrality":degree})
    
    if not node_features:
        for node in GRAPH_NODES_DATA:
            degree = sum(1 for e in GRAPH_EDGES_DATA if e["source"]==node["id"] or e["target"]==node["id"])
            node_features.append({"id":node["id"],"failed_logins":node["anomaly_count"]*2,"api_volume":node["anomaly_count"]*100,"privilege_level":node["privilege_level"],"historical_trust_score":node["historical_trust_score"],"degree_centrality":degree})
    
    try:
        gat_engine = get_gat_engine()
        inference = await gat_engine.run_inference(node_features=node_features,edges=GRAPH_EDGES_DATA,beta=request.beta_weight)
    except Exception as e:
        log.error("GAT inference failed",error=str(e))
        raise HTTPException(status_code=500,detail=f"GAT inference error: {str(e)}")
    
    risk_vectors=[]
    isolation_targets=[]
    for i,node_id in enumerate(inference.node_ids):
        prob=inference.compromise_probabilities[i]; blast=inference.blast_radius_scores[i]
        risk_state=RiskState.COMPROMISED if prob>0.75 else RiskState.AT_RISK if prob>0.4 else RiskState.SAFE
        if prob>0.75: isolation_targets.append(node_id)
        attn=inference.attention_weights_l1[i] if inference.attention_weights_l1 else [0.5]
        risk_vectors.append(NodeRiskVector(node_id=node_id,gat_compromise_probability=round(prob,4),blast_radius_score=round(blast,4),downstream_node_count=inference.downstream_counts[i],risk_state=risk_state,attention_weights=attn[:5],propagation_path=[node_id]))
    
    financial_exposure=sum(v.gat_compromise_probability*1_500_000 for v in risk_vectors)
    return RiskInferenceResponse(node_risk_vectors=risk_vectors,global_blast_radius=round(inference.global_blast_radius,4),estimated_financial_exposure_usd=round(financial_exposure,2),recommended_isolation_targets=isolation_targets[:5])
