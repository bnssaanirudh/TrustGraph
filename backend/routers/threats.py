"""FastAPI Router — Threat Intelligence (/api/threats)"""
from __future__ import annotations
from datetime import datetime
from fastapi import APIRouter, Query
import structlog
from models.schemas import (
    ThreatAlert, ThreatListResponse, ThreatIndicator, SeverityLevel
)

router = APIRouter()
log = structlog.get_logger(__name__)

SEED_THREATS = [
    {"id":"threat_001","title":"VendorX API Gateway Exploit Vector Detected","description":"Threat intel feed flags active CVE exploitation attempt targeting VendorX API gateway. Session tokens observed being reused across 4 distinct IP addresses indicating credential theft and lateral movement initiation.","severity":"critical","affected_vendor_id":"vendor_vendorx","affected_node_ids":["node_api_gw","node_host_01","node_db_customer"],"indicators":[{"ioc_type":"IP","ioc_value":"203.0.113.45","confidence":0.94,"source":"Crowdstrike Falcon"},{"ioc_type":"HASH","ioc_value":"a94f5374fce5edbc8e2a8697cf15041b6197c4e29ef16f0d6f4e1bc9c9c3ecfd","confidence":0.88,"source":"VirusTotal"}],"blast_radius_score":0.89,"estimated_financial_impact_usd":4200000,"mitre_technique_ids":["T1190","T1550.001","T1078"],"status":"active","detected_at":"2024-01-15T08:23:44Z"},
    {"id":"threat_002","title":"Privilege Escalation — Container Cluster svc-cluster-7","description":"Unauthorized EXEC commands executed inside svc-cluster-7 pod. Container escape indicators present: host path mounts detected.","severity":"high","affected_vendor_id":"vendor_acme","affected_node_ids":["node_container_7","node_host_02"],"indicators":[{"ioc_type":"PROCESS","ioc_value":"nsenter --target 1 --mount --uts --ipc --net --pid","confidence":0.97,"source":"Falco Runtime Security"}],"blast_radius_score":0.62,"estimated_financial_impact_usd":850000,"mitre_technique_ids":["T1611","T1548","T1068"],"status":"active","detected_at":"2024-01-15T09:41:22Z"},
    {"id":"threat_003","title":"Unauthorized Database Access — Customer PII Table","description":"Service account db_reader executed 47,000 SELECT queries against customer_pii.users table across 3-hour window. Volume 280x above baseline.","severity":"critical","affected_vendor_id":"vendor_vendorx","affected_node_ids":["node_db_customer","node_host_03"],"indicators":[{"ioc_type":"QUERY_PATTERN","ioc_value":"SELECT * FROM users WHERE created_at > 2020-01-01 LIMIT 10000","confidence":0.91,"source":"DataDog Database Monitoring"}],"blast_radius_score":0.95,"estimated_financial_impact_usd":7800000,"mitre_technique_ids":["T1005","T1213","T1530"],"status":"active","detected_at":"2024-01-15T10:15:08Z"},
    {"id":"threat_004","title":"Suspicious API Volume Spike — PayStream Integration","description":"PayStream Financial vendor API receiving 15,000 requests/hour (normal: 200/hour). Rate limiting bypassed via token rotation.","severity":"high","affected_vendor_id":"vendor_paystream","affected_node_ids":["node_api_paystream","node_host_04"],"indicators":[{"ioc_type":"BEHAVIORAL","ioc_value":"API_VOLUME_ANOMALY_75X_BASELINE","confidence":0.85,"source":"TrustGraph GAT Engine"}],"blast_radius_score":0.71,"estimated_financial_impact_usd":1200000,"mitre_technique_ids":["T1499","T1110"],"status":"investigating","detected_at":"2024-01-15T11:02:33Z"},
    {"id":"threat_005","title":"Session Token Lateral Movement — Database Authentication","description":"Session token originally issued to VendorX API gateway detected authenticating against prod-db-01 via internal transit. Token scope violation.","severity":"critical","affected_vendor_id":"vendor_vendorx","affected_node_ids":["node_api_gw","node_db_prod01","node_host_01"],"indicators":[{"ioc_type":"SESSION_TOKEN","ioc_value":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.REDACTED","confidence":0.99,"source":"OAuth2 Introspection Endpoint"}],"blast_radius_score":0.92,"estimated_financial_impact_usd":6500000,"mitre_technique_ids":["T1550.001","T1021","T1078.004"],"status":"active","detected_at":"2024-01-15T10:55:17Z"},
]

from core.neo4j_client import neo4j_client

@router.post("/threats/reset")
async def reset_database():
    """Clear Neo4j databases before recording demo."""
    try:
        await neo4j_client._execute_write("MATCH (n) DETACH DELETE n")
        return {"status": "success", "message": "Database cleared"}
    except Exception as e:
        log.error("Failed to clear database", error=str(e))
        return {"status": "error", "message": str(e)}

@router.get("/threats", response_model=ThreatListResponse)
async def list_threats(
    severity: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
) -> ThreatListResponse:
    threats = SEED_THREATS.copy()
    if severity:
        threats = [t for t in threats if t.get("severity") == severity]
    if status:
        threats = [t for t in threats if t.get("status") == status]
    threats = threats[:limit]
    
    alert_objects = []
    for t in threats:
        detected = datetime.fromisoformat(t["detected_at"].replace("Z", "+00:00"))
        alert_objects.append(ThreatAlert(
            id=t["id"], title=t["title"], description=t["description"],
            severity=SeverityLevel(t["severity"]),
            affected_vendor_id=t.get("affected_vendor_id"),
            affected_node_ids=t.get("affected_node_ids", []),
            indicators=[ThreatIndicator(**i) for i in t.get("indicators", [])],
            blast_radius_score=t["blast_radius_score"],
            estimated_financial_impact_usd=t["estimated_financial_impact_usd"],
            mitre_technique_ids=t.get("mitre_technique_ids", []),
            detected_at=detected, status=t["status"],
        ))
    
    return ThreatListResponse(
        total=len(alert_objects), alerts=alert_objects,
        global_trust_index=34.7, mttc_minutes=127.4, active_hunt_loops=3,
    )
