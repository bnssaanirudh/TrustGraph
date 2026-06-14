"""FastAPI Router — Vendor Management (/api/vendors)"""
from __future__ import annotations
import random
from datetime import datetime
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query, status
import structlog

from models.schemas import VendorCreate, VendorResponse, RiskState, ComplianceStatus, SeverityLevel
from core.neo4j_client import neo4j_client

router = APIRouter()
log = structlog.get_logger(__name__)

# ─── Seed Vendor Data ──────────────────────────────────────────────────────────
SEED_VENDORS = [
    {"id":"vendor_vendorx","name":"VendorX API Solutions","category":"API Integration","country":"United States","risk_score":91.2,"anomaly_count":47,"api_key_rotations":2,"data_access_volume_gb":2340.5,"privilege_level":4,"ip_address":"203.0.113.45","gat_compromise_score":0.89,"historical_trust_score":0.11,"cryptographic_standard":"TLS1.2/RC4","risk_state":"compromised","contact_email":"security@vendorx.com","compliance_soc2":"non_compliant","compliance_iso27001":"non_compliant","compliance_gdpr":"partial","graph_dependency_depth":6},
    {"id":"vendor_acme","name":"Acme Cloud Services","category":"Cloud Infrastructure","country":"Germany","risk_score":62.4,"anomaly_count":8,"api_key_rotations":12,"data_access_volume_gb":890.2,"privilege_level":3,"ip_address":"198.51.100.20","gat_compromise_score":0.41,"historical_trust_score":0.60,"cryptographic_standard":"TLS1.3/AES256","risk_state":"at_risk","contact_email":"security@acme-cloud.de","compliance_soc2":"compliant","compliance_iso27001":"partial","compliance_gdpr":"compliant","graph_dependency_depth":3},
    {"id":"vendor_databridge","name":"DataBridge Analytics","category":"Data Analytics","country":"United Kingdom","risk_score":44.1,"anomaly_count":3,"api_key_rotations":24,"data_access_volume_gb":445.8,"privilege_level":2,"ip_address":"192.0.2.88","gat_compromise_score":0.22,"historical_trust_score":0.81,"cryptographic_standard":"TLS1.3/AES256","risk_state":"safe","contact_email":"security@databridge.co.uk","compliance_soc2":"compliant","compliance_iso27001":"compliant","compliance_gdpr":"compliant","graph_dependency_depth":2},
    {"id":"vendor_paystream","name":"PayStream Financial","category":"Payment Processing","country":"Singapore","risk_score":78.9,"anomaly_count":21,"api_key_rotations":4,"data_access_volume_gb":1205.3,"privilege_level":4,"ip_address":"198.51.100.55","gat_compromise_score":0.71,"historical_trust_score":0.29,"cryptographic_standard":"TLS1.3/AES256","risk_state":"at_risk","contact_email":"security@paystream.sg","compliance_soc2":"partial","compliance_iso27001":"compliant","compliance_gdpr":"under_review","graph_dependency_depth":4},
    {"id":"vendor_secureauth","name":"SecureAuth Identity","category":"Identity & Access","country":"Netherlands","risk_score":28.3,"anomaly_count":1,"api_key_rotations":36,"data_access_volume_gb":122.9,"privilege_level":5,"ip_address":"198.51.100.71","gat_compromise_score":0.09,"historical_trust_score":0.94,"cryptographic_standard":"TLS1.3/ChaCha20","risk_state":"safe","contact_email":"security@secureauth.nl","compliance_soc2":"compliant","compliance_iso27001":"compliant","compliance_gdpr":"compliant","graph_dependency_depth":1},
    {"id":"vendor_logistix","name":"Logistix Supply Chain","category":"Logistics & Supply","country":"Japan","risk_score":55.7,"anomaly_count":12,"api_key_rotations":8,"data_access_volume_gb":678.4,"privilege_level":2,"ip_address":"203.0.113.102","gat_compromise_score":0.35,"historical_trust_score":0.68,"cryptographic_standard":"TLS1.3/AES256","risk_state":"at_risk","contact_email":"security@logistix.co.jp","compliance_soc2":"compliant","compliance_iso27001":"partial","compliance_gdpr":"under_review","graph_dependency_depth":2},
]


@router.get("/vendors", response_model=list[VendorResponse], summary="List all vendor entities")
async def list_vendors(
    risk_state: str | None = Query(None, description="Filter by risk state"),
    min_risk_score: float = Query(0.0, ge=0.0, le=100.0),
    limit: int = Query(50, ge=1, le=200),
) -> list[VendorResponse]:
    """
    Retrieve all registered third-party vendor entities with risk metadata.
    Supports filtering by risk state and minimum risk score threshold.
    """
    try:
        vendors = SEED_VENDORS.copy()
        
        if risk_state:
            vendors = [v for v in vendors if v.get("risk_state") == risk_state]
        vendors = [v for v in vendors if v.get("risk_score", 0) >= min_risk_score]
        vendors = vendors[:limit]
        
        result = []
        for v in vendors:
            result.append(VendorResponse(
                id=v["id"], name=v["name"], category=v["category"],
                country=v["country"], contact_email=v["contact_email"],
                contract_tier="enterprise" if v["privilege_level"] >= 3 else "standard",
                risk_score=v["risk_score"], api_key_rotations=v["api_key_rotations"],
                anomaly_count=v["anomaly_count"], graph_dependency_depth=v["graph_dependency_depth"],
                compliance_soc2=ComplianceStatus(v["compliance_soc2"]),
                compliance_iso27001=ComplianceStatus(v["compliance_iso27001"]),
                compliance_gdpr=ComplianceStatus(v["compliance_gdpr"]),
                data_access_volume_gb=v["data_access_volume_gb"],
                cryptographic_standard=v["cryptographic_standard"],
                privilege_level=v["privilege_level"],
                risk_state=RiskState(v["risk_state"]),
            ))
        
        log.info("Vendor list retrieved", count=len(result))
        return result
    
    except Exception as e:
        log.error("Vendor list failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/vendors", response_model=VendorResponse, status_code=status.HTTP_201_CREATED,
             summary="Register a new vendor entity")
async def create_vendor(vendor: VendorCreate) -> VendorResponse:
    """Register a new third-party vendor with full risk metadata and graph node creation."""
    vendor_id = f"vendor_{vendor.name.lower().replace(' ', '_')[:20]}_{str(uuid4())[:8]}"
    
    vendor_data = {
        "id": vendor_id,
        "name": vendor.name,
        "category": vendor.category,
        "country": vendor.country,
        "ip_address": "0.0.0.0",
        "privilege_level": vendor.privilege_level,
        "risk_score": vendor.risk_score,
        "anomaly_count": 0,
        "api_key_rotations": 0,
        "cryptographic_standard": vendor.cryptographic_standard,
        "data_access_volume_gb": vendor.data_access_volume_gb,
        "gat_compromise_score": 0.0,
        "historical_trust_score": max(0.0, 1.0 - vendor.risk_score / 100.0),
    }
    
    try:
        await neo4j_client.upsert_vendor(vendor_data)
    except Exception as e:
        log.warning("Neo4j write skipped (offline mode)", error=str(e))
    
    return VendorResponse(
        id=vendor_id, **vendor.model_dump(),
        api_key_rotations=0, anomaly_count=0, graph_dependency_depth=0,
        risk_state=RiskState.SAFE,
    )


@router.get("/vendors/{vendor_id}", response_model=VendorResponse)
async def get_vendor(vendor_id: str) -> VendorResponse:
    """Retrieve detailed profile for a specific vendor by ID."""
    vendor = next((v for v in SEED_VENDORS if v["id"] == vendor_id), None)
    if not vendor:
        raise HTTPException(status_code=404, detail=f"Vendor '{vendor_id}' not found")
    
    return VendorResponse(
        id=vendor["id"], name=vendor["name"], category=vendor["category"],
        country=vendor["country"], contact_email=vendor["contact_email"],
        contract_tier="enterprise" if vendor["privilege_level"] >= 3 else "standard",
        risk_score=vendor["risk_score"], api_key_rotations=vendor["api_key_rotations"],
        anomaly_count=vendor["anomaly_count"], graph_dependency_depth=vendor["graph_dependency_depth"],
        compliance_soc2=ComplianceStatus(vendor["compliance_soc2"]),
        compliance_iso27001=ComplianceStatus(vendor["compliance_iso27001"]),
        compliance_gdpr=ComplianceStatus(vendor["compliance_gdpr"]),
        data_access_volume_gb=vendor["data_access_volume_gb"],
        cryptographic_standard=vendor["cryptographic_standard"],
        privilege_level=vendor["privilege_level"],
        risk_state=RiskState(vendor["risk_state"]),
    )
