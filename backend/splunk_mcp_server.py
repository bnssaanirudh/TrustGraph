"""
Splunk MCP (Model Context Protocol) Server Daemon
Listens for JSON-RPC MCP requests from the TrustGraph backend on port 8080.
Acts as a middleware broker, querying real Splunk instances via REST APIs
or returning realistic security telemetry in mock/simulation mode.
"""
import os
import json
import logging
import time
from typing import Any, Dict, List
from datetime import datetime, timedelta
import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Header, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Initialize logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("splunk-mcp-server")

app = FastAPI(
    title="Splunk MCP Server Daemon",
    description="Model Context Protocol server for Splunk SIEM integration",
    version="1.0.0"
)

# Config options from environment
SPLUNK_URL = os.getenv("SPLUNK_URL", "https://localhost:8089")  # e.g., https://localhost:8089
SPLUNK_USER = os.getenv("SPLUNK_USER", "anirudh")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "Satya1983@@")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "")
MCP_AUTH_TOKEN = os.getenv("SPLUNK_MCP_TOKEN", "mcp_dev_token_2024")

# ─── Pydantic Schemas ─────────────────────────────────────────────────────────
class MCPParams(BaseModel):
    name: str
    arguments: Dict[str, Any]

class MCPRequest(BaseModel):
    jsonrpc: str
    method: str
    id: int
    params: MCPParams

# ─── Real Splunk Client ────────────────────────────────────────────────────────
async def query_real_splunk(query: str, earliest_time: str, latest_time: str) -> Dict[str, Any]:
    """Connects to real Splunk Enterprise REST API to execute search jobs."""
    if not SPLUNK_URL:
        raise ValueError("SPLUNK_URL environment variable is not set")
    
    headers = {}
    if SPLUNK_TOKEN:
        headers["Authorization"] = f"Bearer {SPLUNK_TOKEN}"
    
    # Run a oneshot search via Splunk REST API
    # Endpoint: /services/search/jobs
    search_url = f"{SPLUNK_URL.rstrip('/')}/services/search/jobs"
    
    # SPL queries must start with 'search ' in Splunk REST API if not implicit
    formatted_query = query.strip()
    if not formatted_query.startswith("search") and not formatted_query.startswith("|"):
        formatted_query = f"search {formatted_query}"
        
    data = {
        "search": formatted_query,
        "earliest_time": earliest_time,
        "latest_time": latest_time,
        "output_mode": "json",
        "exec_mode": "oneshot",
        "count": 1000
    }
    
    logger.info(f"Dispatching query to real Splunk REST API: {formatted_query[:100]}...")
    
    async with httpx.AsyncClient(verify=False) as client:
        # If using basic authentication
        auth = None
        if not SPLUNK_TOKEN and SPLUNK_USER and SPLUNK_PASSWORD:
            auth = (SPLUNK_USER, SPLUNK_PASSWORD)
            
        response = await client.post(
            search_url,
            data=data,
            headers=headers,
            auth=auth,
            timeout=30.0
        )
        response.raise_for_status()
        
        # Parse standard Splunk REST results format
        results_payload = response.json()
        
        # Map Splunk fields into results key
        results = results_payload.get("results", [])
        logger.info(f"Real Splunk API returned {len(results)} records")
        return {"results": results, "status": "splunk_rest_api"}

# ─── Simulated Telemetry Ingress ──────────────────────────────────────────────
def generate_simulated_telemetry(query: str) -> Dict[str, Any]:
    """Generates hyper-realistic log telemetry mapping the simulated breach."""
    query_lower = query.lower()
    results = []
    now = datetime.utcnow()
    
    # Seed values mirroring seed_data.py
    if "session_token_movement" in query_lower or "token" in query_lower:
        logger.info("Serving simulated credential/session token anomaly logs")
        results = [
            {
                "_time": (now - timedelta(minutes=195)).isoformat() + "Z",
                "src_ip": "203.0.113.45",
                "dest_host": "web-prod-01",
                "user": "vendorx_svc",
                "action": "TOKEN_USE",
                "count": 47,
                "token_hijack_score": 58.2,
                "severity": "critical",
                "vendor_id": "vendor_vendorx",
                "session_id": "session_tok_hijack_vendorx_912",
                "sourcetype": "oauth2"
            },
            {
                "_time": (now - timedelta(minutes=180)).isoformat() + "Z",
                "src_ip": "198.51.100.55",
                "dest_host": "pay-proxy-01",
                "user": "paystream_api_user",
                "action": "SESSION_EXTEND",
                "count": 21,
                "token_hijack_score": 12.4,
                "severity": "high",
                "vendor_id": "vendor_paystream",
                "session_id": "session_paystream_token_8a3",
                "sourcetype": "iam"
            }
        ]
    elif "lateral_movement" in query_lower or "auth" in query_lower:
        logger.info("Serving simulated lateral host pivot anomaly logs")
        results = [
            {
                "_time": (now - timedelta(minutes=182)).isoformat() + "Z",
                "src_ip": "203.0.113.45",
                "dest_host": "node_host_01",
                "user": "vendorx_svc",
                "action": "AUTHENTICATE",
                "count": 21,
                "anomaly_score": 0.74,
                "severity": "high",
                "vendor_id": "vendor_vendorx",
                "sourcetype": "auth"
            }
        ]
    elif "container_breach" in query_lower or "kubernetes" in query_lower:
        logger.info("Serving simulated container escape anomaly logs")
        results = [
            {
                "_time": (now - timedelta(minutes=132)).isoformat() + "Z",
                "src_ip": "172.16.7.7",
                "dest_host": "node_user_svc7",
                "user": "svc_account_7",
                "cluster_name": "node_container_7",
                "pod_name": "svc-cluster-7",
                "action": "EXEC",
                "count": 15,
                "anomaly_score": 0.68,
                "severity": "high",
                "vendor_id": "vendor_acme",
                "sourcetype": "kubernetes"
            }
        ]
    elif "database_access" in query_lower or "db" in query_lower or "customer_pii" in query_lower:
        logger.info("Serving simulated database exfiltration audit logs")
        results = [
            {
                "_time": (now - timedelta(minutes=95)).isoformat() + "Z",
                "src_ip": "10.0.1.45",
                "dest_host": "node_db_customer",
                "user": "svc_account_7",
                "database_name": "customer_pii",
                "client_host": "svc_account_7",
                "action": "SELECT",
                "query_count": 47000,
                "unique_tables": 3,
                "total_rows": 1284520,
                "gb_transferred": 1.07,
                "anomaly_score": 0.91,
                "severity": "critical",
                "vendor_id": "vendor_vendorx",
                "sourcetype": "db_audit"
            },
            {
                "_time": (now - timedelta(minutes=86)).isoformat() + "Z",
                "src_ip": "10.0.1.45",
                "dest_host": "node_db_prod01",
                "user": "svc_account_7",
                "database_name": "prod-db-01",
                "client_host": "svc_account_7",
                "action": "SELECT",
                "query_count": 34000,
                "unique_tables": 1,
                "total_rows": 524288,
                "gb_transferred": 0.52,
                "anomaly_score": 0.82,
                "severity": "critical",
                "vendor_id": "vendor_vendorx",
                "sourcetype": "db_audit"
            }
        ]
    else:
        logger.info("Serving general API gateway traffic telemetry logs")
        results = [
            {
                "_time": now.isoformat() + "Z",
                "src_ip": "203.0.113.45",
                "dest_host": "node_api_gw",
                "user": "unknown",
                "action": "ingress",
                "count": 512,
                "anomaly_score": 0.12,
                "severity": "medium",
                "vendor_id": "vendor_vendorx",
                "sourcetype": "api_gateway"
            }
        ]
        
    return {"results": results, "status": "simulation_mode", "query_preview": query[:80]}

# ─── Endpoint Router ──────────────────────────────────────────────────────────
@app.post("/mcp")
async def mcp_broker(
    request: Request,
    payload: MCPRequest,
    authorization: str = Header(None)
):
    """MCP JSON-RPC Broker endpoint."""
    logger.info(f"Incoming MCP Request method: {payload.method}, id: {payload.id}")
    
    # 1. Authenticate Token
    if authorization:
        token = authorization.replace("Bearer ", "").strip()
    else:
        token = ""
        
    if token != MCP_AUTH_TOKEN:
        logger.warning(f"Unauthorized MCP attempt with token: {token}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing MCP authorization credentials"
        )
        
    # 2. Verify Tool Call
    if payload.method != "tools/call":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Method '{payload.method}' not supported. Must be 'tools/call'."
        )
        
    tool_name = payload.params.name
    arguments = payload.params.arguments
    
    if tool_name != "splunk_search":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tool '{tool_name}' not supported. Expected 'splunk_search'."
        )
        
    spl_query = arguments.get("query", "")
    earliest = arguments.get("earliest_time", "-24h")
    latest = arguments.get("latest_time", "now")
    
    # 3. Query Splunk or Fallback
    try:
        if SPLUNK_URL:
            logger.info("Routing query to real Splunk Enterprise REST service...")
            splunk_data = await query_real_splunk(spl_query, earliest, latest)
        else:
            logger.info("No active SPLUNK_URL — running search in mock simulation mode")
            splunk_data = generate_simulated_telemetry(spl_query)
    except Exception as e:
        logger.error(f"Error executing Splunk query: {e}")
        # Fallback to simulated data so backend does not break
        splunk_data = generate_simulated_telemetry(spl_query)
        splunk_data["error"] = str(e)
        
    # 4. Construct JSON-RPC standard response
    # result.content[0].text must contain the stringified JSON payload
    response_payload = {
        "jsonrpc": "2.0",
        "id": payload.id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(splunk_data)
                }
            ]
        }
    }
    
    return JSONResponse(content=response_payload)

@app.get("/health")
async def health():
    return {
        "status": "online",
        "mcp_server": "Splunk Broker",
        "mode": "production" if SPLUNK_URL else "simulation_mode",
        "mcp_port": 8080
    }

if __name__ == "__main__":
    logger.info(f"Starting Splunk MCP Daemon on port 8080...")
    logger.info(f"Mode: {'REAL SPLUNK (' + SPLUNK_URL + ')' if SPLUNK_URL else 'MOCK SIMULATION'}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
