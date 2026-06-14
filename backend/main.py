"""
TrustGraph FastAPI Backend — Main Application Entry Point
Production-grade async API with strict Pydantic v2 typing,
structured logging, and CORS configuration.
"""
import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

import structlog
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from routers import vendors, threats, graph, risk, investigate
from core.neo4j_client import neo4j_client
from core.splunk_mcp import run_mcp_spl_query
from core.gat_model import get_gat_engine

# ─── Background Service ──────────────────────────────────────────────────────
async def splunk_ingestion_loop():
    """Continuously polls Splunk MCP, updates Neo4j, and runs GAT model."""
    log.info("Starting Splunk MCP background ingestion loop")
    while True:
        try:
            # 1. Fetch live telemetry via LangGraph/MCP Splunk Integration
            telemetry_records = await run_mcp_spl_query(
                "Detect lateral movement, container escapes, or database exfiltration anomalies",
                "24h"
            )
            if telemetry_records:
                log.info(f"Ingesting {len(telemetry_records)} records into Neo4j graph...")
                # 2. Link Splunk MCP Output to Neo4j
                await neo4j_client.ingest_splunk_logs(telemetry_records)
                
                # 3. Run PyTorch GAT Model on the Graph State
                graph_state = await neo4j_client.get_graph_topology()
                gat_engine = get_gat_engine()
                inference_result = await gat_engine.run_inference(
                    node_features=graph_state.get("nodes", []),
                    edges=graph_state.get("edges", []),
                    beta=0.7
                )
                
                # Push risk scores back into Neo4j
                for i, node_id in enumerate(inference_result.node_ids):
                    risk_score = inference_result.compromise_probabilities[i]
                    risk_state = "critical" if risk_score > 0.85 else "high" if risk_score > 0.5 else "elevated" if risk_score > 0.2 else "safe"
                    await neo4j_client.update_node_risk_state(node_id, risk_state, risk_score)
                    
                log.info("GAT Risk scoring complete and synchronized to Neo4j")
        except Exception as e:
            log.error(f"Error in background ingestion loop: {str(e)}")
        
        # Poll every 10 seconds for real-time live demo updates
        await asyncio.sleep(10)

# ─── Structured Logging Setup ────────────────────────────────────────────────
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)
log = structlog.get_logger(__name__)

# ─── Application Lifespan ─────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle manager."""
    log.info("TrustGraph platform initializing...", version="1.0.0")
    try:
        await neo4j_client.verify_connectivity()
        log.info("Neo4j connection verified")
    except Exception as e:
        log.warning("Neo4j unavailable — running in offline mode", error=str(e))
    
    log.info("TrustGraph API ready", endpoints=5)
    
    # Start background loop
    task = asyncio.create_task(splunk_ingestion_loop())
    
    yield
    
    # Graceful shutdown
    task.cancel()
    await neo4j_client.close()
    log.info("TrustGraph platform shutting down")


# ─── FastAPI Application ──────────────────────────────────────────────────────
app = FastAPI(
    title="TrustGraph API",
    description="Agentic Third-Party Risk & Threat Hunting Platform — Production API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# ─── CORS Middleware ──────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "https://trustgraph.security",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Request Logging Middleware ───────────────────────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = asyncio.get_event_loop().time()
    response = await call_next(request)
    duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
    log.info(
        "HTTP request processed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=round(duration_ms, 2),
    )
    return response

# ─── Global Exception Handler ─────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.error("Unhandled exception", path=request.url.path, error=str(exc), exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred in the TrustGraph engine.",
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(request.url.path),
        },
    )

# ─── Router Registration ──────────────────────────────────────────────────────
app.include_router(vendors, prefix="/api", tags=["Vendor Management"])
app.include_router(threats, prefix="/api", tags=["Threat Intelligence"])
app.include_router(graph, prefix="/api", tags=["Graph Topology"])
app.include_router(risk, prefix="/api", tags=["Risk Engine"])
app.include_router(investigate, prefix="/api", tags=["CARAG Investigation"])

# ─── Health Probe ─────────────────────────────────────────────────────────────
@app.get("/api/health", tags=["System"])
async def health_check() -> dict[str, Any]:
    """System health probe for load balancer and monitoring integration."""
    return {
        "status": "operational",
        "platform": "TrustGraph",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "api": "healthy",
            "neo4j": await neo4j_client.ping(),
            "gat_engine": "ready",
            "carag_pipeline": "ready",
        },
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
        access_log=True,
    )
