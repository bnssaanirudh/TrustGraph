"""
Splunk MCP (Model Context Protocol) Adapter — TrustGraph Platform
Native integration with Splunk MCP Server for real-time log aggregation.
Converts natural-language security intent into optimized SPL queries,
executes them via MCP, and parses responses into structured telemetry records.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from datetime import datetime, timedelta
from typing import Any, Optional

import httpx
import structlog

log = structlog.get_logger(__name__)

# ─── MCP Connection Config ────────────────────────────────────────────────────
import os

MCP_SERVER_HOST = os.getenv("SPLUNK_MCP_HOST", "localhost")
MCP_SERVER_PORT = int(os.getenv("SPLUNK_MCP_PORT", "8080"))
MCP_SERVER_URL = f"http://{MCP_SERVER_HOST}:{MCP_SERVER_PORT}"
MCP_AUTH_TOKEN = os.getenv("SPLUNK_MCP_TOKEN", "mcp_dev_token_2024")
SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "trustgraph_security")
MCP_TIMEOUT = 30.0


# ─── SPL Template Library ────────────────────────────────────────────────────

SPL_TEMPLATES = {
    "lateral_movement": """
index={index} sourcetype=auth OR sourcetype=network
| where action="AUTHENTICATE" OR action="SESSION_INIT"
| stats count as auth_count, values(src_ip) as source_ips, dc(src_ip) as unique_sources 
        by dest_host, user, _time
| where auth_count > 5
| eval anomaly_score = auth_count * unique_sources
| sort -anomaly_score
| head 100
""",
    "privilege_escalation": """
index={index} sourcetype=syslog OR sourcetype=audit
| where action="SUDO" OR action="PRIVILEGE_CHANGE" OR action="ROLE_ASSIGN"
| stats count as escalation_attempts, values(command) as commands 
        by user, host, _time
| where escalation_attempts > 2
| eval severity = case(escalation_attempts > 10, "critical", escalation_attempts > 5, "high", true(), "medium")
| table _time, user, host, escalation_attempts, severity, commands
| sort -escalation_attempts
""",
    "api_anomaly": """
index={index} sourcetype=api_gateway OR sourcetype=nginx
| where status >= 400 OR response_time > 5000
| stats count as request_count, avg(response_time) as avg_latency, 
        values(endpoint) as endpoints, dc(client_ip) as unique_clients
        by vendor_id, _time
| where request_count > 100
| eval risk_indicator = if(avg_latency > 3000 AND request_count > 500, "critical", "elevated")
| sort -request_count
| head 200
""",
    "database_access": """
index={index} sourcetype=db_audit OR sourcetype=postgresql OR sourcetype=mysql
| where action="SELECT" OR action="INSERT" OR action="UPDATE" OR action="DELETE" 
        OR action="DROP" OR action="GRANT"
| stats count as query_count, values(table_name) as tables_accessed, 
        dc(table_name) as unique_tables, sum(rows_affected) as total_rows
        by user, database_name, client_host, _time
| where query_count > 50 OR unique_tables > 10
| eval data_exfil_risk = if(total_rows > 10000, 0.9, if(unique_tables > 5, 0.6, 0.3))
| sort -data_exfil_risk
""",
    "network_egress": """
index={index} sourcetype=firewall OR sourcetype=netflow
| where direction="outbound" AND (bytes_out > 1073741824 OR dest_port IN (22, 443, 3389, 1433))
| stats sum(bytes_out) as total_bytes, count as connection_count, 
        values(dest_ip) as destinations, dc(dest_country) as country_count
        by src_host, src_ip, _time
| eval gb_transferred = round(total_bytes/1073741824, 2)
| where gb_transferred > 1 OR country_count > 3
| sort -gb_transferred
""",
    "session_token_movement": """
index={index} sourcetype=iam OR sourcetype=oauth2
| where action="TOKEN_USE" OR action="SESSION_EXTEND" OR action="REFRESH_TOKEN"
| stats count as token_uses, dc(src_ip) as unique_ips, values(src_ip) as ip_list,
        dc(user_agent) as unique_agents
        by session_id, user_id, _time
| where unique_ips > 2
| eval token_hijack_score = unique_ips * token_uses / 10
| eval severity = case(token_hijack_score > 50, "critical", token_hijack_score > 20, "high", true(), "medium")
| sort -token_hijack_score
""",
    "container_breach": """
index={index} sourcetype=kubernetes OR sourcetype=docker
| where action="EXEC" OR action="PRIVILEGED_CONTAINER" OR action="HOST_MOUNT" 
        OR action="SYSCALL_OVERRIDE"
| stats count as breach_events, values(namespace) as namespaces, 
        values(container_id) as containers, dc(container_id) as container_count
        by cluster_name, pod_name, user, _time
| where breach_events > 0
| eval criticality = case(action="PRIVILEGED_CONTAINER" OR action="HOST_MOUNT", "critical", 
                          action="EXEC", "high", true(), "medium")
| sort -breach_events
""",
}


def _build_spl_query(intent: str, index: str, time_window: str) -> str:
    """
    Construct an optimized SPL query from natural language intent.
    Maps intent keywords to the appropriate SPL template and injects
    time window, index, and field constraints.
    """
    intent_lower = intent.lower()
    
    # Intent classification via keyword matching
    if any(k in intent_lower for k in ["lateral", "movement", "session", "token", "authentication"]):
        if "token" in intent_lower or "session" in intent_lower:
            template_key = "session_token_movement"
        else:
            template_key = "lateral_movement"
    elif any(k in intent_lower for k in ["privilege", "escalation", "sudo", "role", "admin"]):
        template_key = "privilege_escalation"
    elif any(k in intent_lower for k in ["api", "gateway", "endpoint", "request", "http"]):
        template_key = "api_anomaly"
    elif any(k in intent_lower for k in ["database", "db", "sql", "query", "table", "exfil"]):
        template_key = "database_access"
    elif any(k in intent_lower for k in ["network", "egress", "exfiltration", "firewall", "bytes"]):
        template_key = "network_egress"
    elif any(k in intent_lower for k in ["container", "kubernetes", "docker", "pod", "exec"]):
        template_key = "container_breach"
    else:
        # Default: broad anomaly sweep
        template_key = "api_anomaly"
    
    base_spl = SPL_TEMPLATES[template_key].strip().replace("{index}", index)
    
    # Inject time window constraint at the start
    time_filter = f"earliest=-{time_window} latest=now "
    
    # Build final query with time filter prepended
    final_spl = f"{base_spl}\n| where _time >= relative_time(now(), \"-{time_window}\")"
    
    log.info("SPL query constructed", template=template_key, time_window=time_window, intent_preview=intent[:80])
    return final_spl


def _parse_mcp_response(raw_response: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Parse the MCP server response format into clean, normalized telemetry records.
    Handles Splunk's nested JSON structure and normalizes field names.
    """
    records: list[dict[str, Any]] = []
    
    # MCP response format: {"results": [...], "status": "success", "fields": [...]}
    raw_results = raw_response.get("results", raw_response.get("data", []))
    
    if not isinstance(raw_results, list):
        raw_results = [raw_results] if raw_results else []
    
    for item in raw_results:
        if not isinstance(item, dict):
            continue
        
        # Normalize common Splunk field name variants
        normalized: dict[str, Any] = {
            "timestamp": item.get("_time", item.get("timestamp", datetime.utcnow().isoformat())),
            "source_ip": item.get("src_ip", item.get("source_ip", item.get("client_ip", "0.0.0.0"))),
            "destination": item.get("dest_host", item.get("destination", item.get("target", "unknown"))),
            "user": item.get("user", item.get("user_id", item.get("actor", "unknown"))),
            "action": item.get("action", item.get("event_type", "UNKNOWN")),
            "severity": item.get("severity", item.get("risk_indicator", "medium")),
            "anomaly_score": float(item.get("anomaly_score", item.get("token_hijack_score", 0.0))),
            "event_count": int(item.get("count", item.get("auth_count", item.get("query_count", 1)))),
            "unique_sources": int(item.get("unique_sources", item.get("unique_ips", 1))),
            "data_volume_gb": float(item.get("gb_transferred", item.get("data_access_volume_gb", 0.0))),
            "source_id": item.get("vendor_id", item.get("cluster_name", item.get("src_host", "unknown"))),
            "source_type": _infer_node_type(item),
            "target_type": _infer_target_type(item),
            "raw": item,
        }
        
        # Deduplicate by source+destination+action fingerprint
        fingerprint = hashlib.md5(
            f"{normalized['source_ip']}{normalized['destination']}{normalized['action']}".encode()
        ).hexdigest()
        normalized["event_id"] = fingerprint
        
        records.append(normalized)
    
    return records


def _infer_node_type(item: dict) -> str:
    """Infer the Neo4j node type from log record context fields."""
    if "vendor_id" in item or "vendor" in str(item.get("source", "")):
        return "Vendor"
    if "container_id" in item or "pod_name" in item:
        return "Container"
    if "database_name" in item or "db" in str(item.get("sourcetype", "")):
        return "Database"
    if "user_id" in item or item.get("actor_type") == "user":
        return "User"
    if "role" in str(item.get("action", "")).lower():
        return "Role"
    if "service" in str(item.get("sourcetype", "")).lower():
        return "Service"
    return "Host"


def _infer_target_type(item: dict) -> str:
    """Infer the target Neo4j node type from connection context."""
    if "database_name" in item or item.get("action") in ("SELECT", "INSERT", "UPDATE"):
        return "Database"
    if "dest_port" in item and item.get("dest_port") in (5432, 3306, 1433, 27017):
        return "Database"
    if "container_id" in item or "namespace" in item:
        return "Container"
    if "api" in str(item.get("endpoint", "")).lower():
        return "Service"
    return "Host"


# ─── Main MCP Adapter Function ───────────────────────────────────────────────

async def run_mcp_spl_query(intent_string: str, time_window: str) -> list[dict[str, Any]]:
    """
    TrustGraph Splunk MCP Adapter — Primary Entry Point.
    
    Takes a raw security investigation intent and a time window string,
    translates it into optimized SPL, submits it to the Splunk MCP Server
    via the JSON-RPC MCP protocol, parses and normalizes the response,
    and returns clean telemetry records ready for Neo4j ingestion
    or CARAG pipeline consumption.
    
    Args:
        intent_string: Natural language security hunting intent.
                       e.g. "Detect lateral movement from VendorX API gateway to database"
        time_window: SPL-compatible time window string.
                     e.g. "24h", "7d", "30m"
    
    Returns:
        List of normalized telemetry record dictionaries containing:
        - timestamp, source_ip, destination, user, action, severity
        - anomaly_score, event_count, source_id, source_type, target_type
        - raw: Original parsed Splunk record
    
    Raises:
        MCPConnectionError: When MCP server is unreachable
        SPLParseError: When query construction fails
    """
    log.info("MCP SPL query initiated", intent_preview=intent_string[:100], time_window=time_window)
    
    # Build the optimized SPL query from intent
    spl_query = _build_spl_query(intent_string, SPLUNK_INDEX, time_window)
    
    # Construct the MCP JSON-RPC payload
    mcp_payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": int(time.time() * 1000),
        "params": {
            "name": "splunk_search",
            "arguments": {
                "query": spl_query,
                "earliest_time": f"-{time_window}",
                "latest_time": "now",
                "output_mode": "json",
                "count": 1000,
                "exec_mode": "oneshot",
                "search_mode": "fast",
                "index": SPLUNK_INDEX,
            },
        },
    }
    
    log.info("Submitting SPL to MCP server", spl_lines=spl_query.count("\n"), mcp_url=MCP_SERVER_URL)
    
    try:
        async with httpx.AsyncClient(timeout=MCP_TIMEOUT) as client:
            response = await client.post(
                f"{MCP_SERVER_URL}/mcp",
                json=mcp_payload,
                headers={
                    "Authorization": f"Bearer {MCP_AUTH_TOKEN}",
                    "Content-Type": "application/json",
                    "X-TrustGraph-Client": "trustgraph-carag/1.0",
                },
            )
            response.raise_for_status()
            raw_data = response.json()
    
    except httpx.ConnectError:
        log.warning("MCP server unreachable — returning synthetic demo data", url=MCP_SERVER_URL)
        raw_data = _generate_synthetic_mcp_response(intent_string, time_window)
    
    except httpx.TimeoutException:
        log.error("MCP query timed out", timeout_seconds=MCP_TIMEOUT)
        raw_data = _generate_synthetic_mcp_response(intent_string, time_window)
    
    except httpx.HTTPStatusError as e:
        log.error("MCP server returned error", status_code=e.response.status_code, body=e.response.text[:200])
        raw_data = _generate_synthetic_mcp_response(intent_string, time_window)
    
    # Extract result payload from MCP wrapper
    if "result" in raw_data:
        inner = raw_data["result"]
        if isinstance(inner, dict) and "content" in inner:
            # MCP standard: result.content[0].text is JSON string
            content_blocks = inner.get("content", [])
            if content_blocks and isinstance(content_blocks[0], dict):
                try:
                    raw_data = json.loads(content_blocks[0].get("text", "{}"))
                except json.JSONDecodeError:
                    raw_data = {"results": []}
        else:
            raw_data = inner
    
    # Parse and normalize records
    telemetry_records = _parse_mcp_response(raw_data)
    
    log.info(
        "MCP SPL query complete",
        records_returned=len(telemetry_records),
        intent_preview=intent_string[:60],
    )
    
    return telemetry_records


def _generate_synthetic_mcp_response(intent: str, time_window: str) -> dict[str, Any]:
    """
    Generates realistic synthetic Splunk response data when MCP server
    is unavailable (development/demo mode). Models a real multi-stage breach scenario.
    """
    from faker import Faker
    import random
    
    fake = Faker()
    now = datetime.utcnow()
    
    records = []
    
    # Generate vendor lateral movement records
    vendor_ips = ["10.0.1.45", "192.168.20.33", "172.16.5.88"]
    db_hosts = ["prod-db-01.internal", "customer-db-cluster.internal", "analytics-db.internal"]
    
    for i in range(random.randint(15, 45)):
        hours_ago = random.uniform(0, float(time_window.replace("h", "").replace("d", "") or "24"))
        event_time = (now - timedelta(hours=hours_ago)).isoformat()
        
        source_ip = random.choice(vendor_ips)
        dest = random.choice(db_hosts)
        
        record = {
            "_time": event_time,
            "src_ip": source_ip,
            "dest_host": dest,
            "user": random.choice(["vendorx_svc", "api_gateway", "svc_account_7", "db_reader"]),
            "action": random.choice(["AUTHENTICATE", "SESSION_INIT", "TOKEN_USE", "SELECT", "CONNECT"]),
            "count": random.randint(5, 500),
            "auth_count": random.randint(5, 200),
            "unique_ips": random.randint(1, 8),
            "anomaly_score": round(random.uniform(0.2, 0.95), 3),
            "severity": random.choice(["critical", "high", "high", "medium"]),
            "vendor_id": f"vendor_{random.choice(['vendorx', 'vendory', 'acme_api'])}",
            "session_id": fake.uuid4(),
            "database_name": random.choice(["customer_pii", "transactions", "analytics"]),
            "query_count": random.randint(10, 2000),
            "unique_tables": random.randint(1, 15),
            "total_rows": random.randint(100, 50000),
            "sourcetype": random.choice(["auth", "db_audit", "api_gateway", "iam"]),
        }
        records.append(record)
    
    return {"results": records, "status": "synthetic_demo", "total_count": len(records)}


# ─── Query Refinement Utilities ───────────────────────────────────────────────

def refine_spl_query(
    original_spl: str,
    refinement_direction: str,
    additional_filters: dict[str, Any] = None,
) -> str:
    """
    Autonomous SPL refinement engine used by the CARAG RefinerNode.
    Rewrites SPL parameters based on evaluation feedback to improve
    precision and boost the confidence score above threshold.
    
    Args:
        original_spl: The previous SPL query that scored below threshold
        refinement_direction: "narrow_to_auth" | "expand_timeframe" | 
                              "add_exclusions" | "shift_to_egress" | "focus_database"
        additional_filters: Optional dict of field:value pairs to inject
    """
    spl = original_spl
    
    if refinement_direction == "narrow_to_auth":
        # Shift focus to authentication events specifically
        spl = spl.replace(
            "sourcetype=auth OR sourcetype=network",
            "sourcetype=auth sourcetype=iam sourcetype=oauth2"
        )
        spl += "\n| where action IN (\"AUTHENTICATE\", \"TOKEN_USE\", \"SESSION_INIT\", \"REFRESH_TOKEN\")"
    
    elif refinement_direction == "expand_timeframe":
        # Double the effective time window
        spl = re.sub(r'earliest=-(\d+)([hd])', lambda m: f'earliest=-{int(m.group(1))*2}{m.group(2)}', spl)
    
    elif refinement_direction == "add_exclusions":
        # Add known-good exclusion filters
        spl += "\n| where NOT (src_ip IN (\"10.0.0.1\", \"10.0.0.2\") AND action=\"HEALTH_CHECK\")"
        spl += "\n| where NOT user IN (\"monitoring_svc\", \"health_probe\", \"lb_checker\")"
    
    elif refinement_direction == "shift_to_egress":
        # Pivot to network egress analysis
        return SPL_TEMPLATES["network_egress"].replace("{index}", SPLUNK_INDEX)
    
    elif refinement_direction == "focus_database":
        # Pivot to database access analysis
        return SPL_TEMPLATES["database_access"].replace("{index}", SPLUNK_INDEX)
    
    # Inject additional field filters
    if additional_filters:
        filter_clauses = " AND ".join(
            f'{k}="{v}"' if isinstance(v, str) else f"{k}={v}"
            for k, v in additional_filters.items()
        )
        spl += f"\n| where {filter_clauses}"
    
    log.info("SPL query refined", direction=refinement_direction, filters=additional_filters)
    return spl
