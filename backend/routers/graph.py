"""FastAPI Router — Graph Topology (/api/graph)"""
from __future__ import annotations
from fastapi import APIRouter
from models.schemas import GraphTopologyResponse, GraphNode, GraphEdge, NodeType, EdgeType, RiskState

router = APIRouter()

from core.neo4j_client import neo4j_client

@router.get("/graph", response_model=GraphTopologyResponse)
async def get_graph_topology() -> GraphTopologyResponse:
    topology = await neo4j_client.get_graph_topology()
    db_nodes = topology.get("nodes", [])
    db_edges = topology.get("edges", [])
    
    # Assign default layout positions if missing
    import random
    nodes = []
    for i, n in enumerate(db_nodes):
        nodes.append(GraphNode(
            id=n.get("id", f"n{i}"),
            label=n.get("label", n.get("id", "")),
            type=NodeType(n.get("type", "Host")),
            ip_address=n.get("ip_address", ""),
            service_tier=n.get("service_tier", "standard"),
            iam_privileges=n.get("iam_privileges", []),
            gat_compromise_score=n.get("gat_compromise_score", 0.0),
            anomaly_count=n.get("anomaly_count", 0),
            privilege_level=n.get("privilege_level", 1),
            historical_trust_score=n.get("historical_trust_score", 1.0),
            risk_state=RiskState(n.get("risk_state", "safe")),
            position_x=n.get("position_x", random.uniform(50, 800)),
            position_y=n.get("position_y", random.uniform(50, 600))
        ))
        
    edges = []
    for i, e in enumerate(db_edges):
        edges.append(GraphEdge(
            id=e.get("id", f"e{i}"),
            source=e.get("source", ""),
            target=e.get("target", ""),
            relationship=EdgeType(e.get("relationship", "CONNECTS")),
            weight=e.get("weight", 1.0),
            anomaly_flagged=e.get("anomaly_flagged", False)
        ))
        
    compromised = sum(1 for n in nodes if n.risk_state == "compromised")
    blast = sum(n.gat_compromise_score for n in nodes if n.gat_compromise_score > 0.5) / max(len(nodes), 1)
    
    return GraphTopologyResponse(
        nodes=nodes,
        edges=edges,
        total_nodes=len(nodes),
        total_edges=len(edges),
        compromised_node_count=compromised,
        blast_radius_surface=round(blast, 4)
    )
