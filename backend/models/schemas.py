"""
Pydantic v2 Schema Models — TrustGraph Platform
Strict typing with detailed validation for all API request/response contracts.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


# ─── Enumerations ─────────────────────────────────────────────────────────────

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskState(str, Enum):
    SAFE = "safe"
    AT_RISK = "at_risk"
    COMPROMISED = "compromised"
    ISOLATED = "isolated"


class NodeType(str, Enum):
    VENDOR = "Vendor"
    SERVICE = "Service"
    CONTAINER = "Container"
    DATABASE = "Database"
    HOST = "Host"
    USER = "User"
    ROLE = "Role"


class EdgeType(str, Enum):
    CALLS = "CALLS"
    AUTHENTICATES = "AUTHENTICATES"
    CONNECTS = "CONNECTS"
    ACCESSES = "ACCESSES"
    DEPLOYS = "DEPLOYS"


class ComplianceStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    UNDER_REVIEW = "under_review"


class CARAGStage(str, Enum):
    PLANNING = "planning"
    RETRIEVING = "retrieving"
    EVALUATING = "evaluating"
    REFINING = "refining"
    MITIGATING = "mitigating"
    COMPLETE = "complete"
    FAILED = "failed"


# ─── Vendor Schemas ───────────────────────────────────────────────────────────

class VendorBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=200, description="Vendor legal entity name")
    category: str = Field(..., description="Vendor service category")
    country: str = Field(..., min_length=2, max_length=100)
    contact_email: str = Field(..., description="Primary security contact email")
    contract_tier: str = Field(default="standard", description="Contract SLA tier")
    risk_score: float = Field(default=50.0, ge=0.0, le=100.0, description="Aggregate risk score 0-100")


class VendorCreate(VendorBase):
    api_key_hash: Optional[str] = Field(None, description="SHA-256 hash of primary API key")
    cryptographic_standard: str = Field(default="TLS1.3/AES256", description="Encryption standard in use")
    data_access_volume_gb: float = Field(default=0.0, ge=0.0)
    privilege_level: int = Field(default=1, ge=1, le=5, description="IAM privilege tier 1-5")


class VendorResponse(VendorBase):
    id: str = Field(default_factory=lambda: str(uuid4()))
    api_key_rotations: int = Field(default=0, description="Total API key rotations logged")
    last_rotation_at: Optional[datetime] = None
    anomaly_count: int = Field(default=0)
    graph_dependency_depth: int = Field(default=0, description="Neo4j downstream node depth")
    compliance_soc2: ComplianceStatus = Field(default=ComplianceStatus.UNDER_REVIEW)
    compliance_iso27001: ComplianceStatus = Field(default=ComplianceStatus.UNDER_REVIEW)
    compliance_gdpr: ComplianceStatus = Field(default=ComplianceStatus.UNDER_REVIEW)
    data_access_volume_gb: float = Field(default=0.0)
    cryptographic_standard: str = Field(default="TLS1.3/AES256")
    privilege_level: int = Field(default=1)
    risk_state: RiskState = Field(default=RiskState.SAFE)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"from_attributes": True}


# ─── Threat Schemas ───────────────────────────────────────────────────────────

class ThreatIndicator(BaseModel):
    ioc_type: str = Field(..., description="Indicator of Compromise type: IP, HASH, DOMAIN, etc.")
    ioc_value: str = Field(..., description="Raw IOC value")
    confidence: float = Field(..., ge=0.0, le=1.0)
    source: str = Field(..., description="Intel feed source")


class ThreatAlert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str = Field(..., min_length=5, max_length=500)
    description: str = Field(..., description="Detailed threat narrative")
    severity: SeverityLevel = Field(...)
    affected_vendor_id: Optional[str] = None
    affected_node_ids: list[str] = Field(default_factory=list)
    indicators: list[ThreatIndicator] = Field(default_factory=list)
    blast_radius_score: float = Field(default=0.0, ge=0.0, le=1.0)
    estimated_financial_impact_usd: float = Field(default=0.0, ge=0.0)
    mitre_technique_ids: list[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    contained_at: Optional[datetime] = None
    status: str = Field(default="active")


class ThreatListResponse(BaseModel):
    total: int
    alerts: list[ThreatAlert]
    global_trust_index: float = Field(..., ge=0.0, le=100.0)
    mttc_minutes: float = Field(..., description="Mean Time to Containment in minutes")
    active_hunt_loops: int


# ─── Graph Topology Schemas ───────────────────────────────────────────────────

class GraphNode(BaseModel):
    id: str
    label: str = Field(..., description="Display label")
    type: NodeType
    ip_address: Optional[str] = None
    service_tier: Optional[str] = None
    iam_privileges: list[str] = Field(default_factory=list)
    gat_compromise_score: float = Field(default=0.0, ge=0.0, le=1.0)
    anomaly_count: int = Field(default=0)
    privilege_level: int = Field(default=1, ge=1, le=5)
    historical_trust_score: float = Field(default=1.0, ge=0.0, le=1.0)
    risk_state: RiskState = Field(default=RiskState.SAFE)
    # React Flow position
    position_x: float = Field(default=0.0)
    position_y: float = Field(default=0.0)


class GraphEdge(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    source: str = Field(..., description="Source node ID")
    target: str = Field(..., description="Target node ID")
    relationship: EdgeType
    weight: float = Field(default=1.0, ge=0.0, le=1.0, description="Edge weight for GAT attention")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    anomaly_flagged: bool = Field(default=False)


class GraphTopologyResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    total_nodes: int
    total_edges: int
    compromised_node_count: int
    blast_radius_surface: float = Field(..., description="Aggregate blast radius 0-1")


# ─── Risk Engine Schemas ──────────────────────────────────────────────────────

class RiskInferenceRequest(BaseModel):
    node_ids: list[str] = Field(..., min_length=1, description="Node IDs to compute risk for")
    topology_snapshot: Optional[dict[str, Any]] = Field(None, description="Optional graph state override")
    beta_weight: float = Field(default=0.7, ge=0.0, le=1.0, description="Beta weight in blast radius formula")
    propagation_depth: int = Field(default=3, ge=1, le=10, description="Maximum hop depth for propagation")


class NodeRiskVector(BaseModel):
    node_id: str
    gat_compromise_probability: float = Field(..., ge=0.0, le=1.0)
    blast_radius_score: float = Field(..., ge=0.0, le=1.0)
    downstream_node_count: int
    risk_state: RiskState
    attention_weights: list[float] = Field(default_factory=list, description="GAT layer attention coefficients")
    propagation_path: list[str] = Field(default_factory=list, description="Risk propagation node path")


class RiskInferenceResponse(BaseModel):
    inference_id: str = Field(default_factory=lambda: str(uuid4()))
    node_risk_vectors: list[NodeRiskVector]
    global_blast_radius: float = Field(..., ge=0.0, le=1.0)
    estimated_financial_exposure_usd: float
    recommended_isolation_targets: list[str]
    computed_at: datetime = Field(default_factory=datetime.utcnow)
    model_version: str = Field(default="gat_v2.0_dual_head")


# ─── CARAG Investigation Schemas ──────────────────────────────────────────────

class InvestigationRequest(BaseModel):
    threat_intent: str = Field(
        ...,
        min_length=10,
        description="Natural language threat hunting intent",
        examples=["Detect lateral movement from VendorX API gateway to database clusters"],
    )
    time_window_hours: int = Field(default=24, ge=1, le=168, description="Investigation time window in hours")
    confidence_threshold: float = Field(default=0.85, ge=0.5, le=1.0)
    max_iterations: int = Field(default=4, ge=1, le=8)
    target_vendor_id: Optional[str] = None
    target_node_ids: list[str] = Field(default_factory=list)


class CARAGLogEntry(BaseModel):
    sequence: int
    stage: CARAGStage
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    action: str
    detail: str
    confidence_score: Optional[float] = None
    spl_query: Optional[str] = None
    logs_retrieved_count: Optional[int] = None


class MitigationAction(BaseModel):
    action_type: str = Field(..., description="disable_iam_role | isolate_container | revoke_api_key | block_egress")
    target_resource: str
    priority: SeverityLevel
    estimated_impact: str
    auto_executable: bool = Field(default=False)
    cypher_mutation: Optional[str] = Field(None, description="Neo4j mutation to apply containment")


class InvestigationResponse(BaseModel):
    investigation_id: str = Field(default_factory=lambda: str(uuid4()))
    status: CARAGStage
    total_iterations: int
    final_confidence_score: float
    agent_ledger: list[CARAGLogEntry]
    retrieved_log_count: int
    threat_summary: str
    blast_radius_nodes: list[str]
    mitigation_plan: list[MitigationAction]
    gat_risk_vectors: list[NodeRiskVector] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
