"""
Neo4j Async Graph Client — TrustGraph Platform
Production async driver using official neo4j Python package with:
- MERGE semantics for idempotent graph writes
- Full property mapping for security context
- Splunk log ingestion pipeline
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any, Optional
import os

import structlog
from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession

log = structlog.get_logger(__name__)

# ─── Connection Config ────────────────────────────────────────────────────────
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "trustgraph2024")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")


class Neo4jClient:
    """
    Async Neo4j client with full graph schema management.
    Implements MERGE-safe writes, Splunk log ingestion, and graph queries.
    """
    
    def __init__(self):
        self._driver: Optional[AsyncDriver] = None
    
    async def _get_driver(self) -> AsyncDriver:
        if self._driver is None:
            self._driver = AsyncGraphDatabase.driver(
                NEO4J_URI,
                auth=(NEO4J_USER, NEO4J_PASSWORD),
                max_connection_lifetime=3600,
                max_connection_pool_size=50,
                connection_acquisition_timeout=60,
            )
        return self._driver
    
    async def close(self):
        if self._driver:
            await self._driver.close()
            self._driver = None
    
    async def ping(self) -> str:
        try:
            driver = await self._get_driver()
            await driver.verify_connectivity()
            return "healthy"
        except Exception:
            return "unavailable"
    
    async def verify_connectivity(self):
        driver = await self._get_driver()
        await driver.verify_connectivity()
    
    async def _execute_write(self, cypher: str, params: dict[str, Any] = None) -> list[dict]:
        """Execute a write transaction and return results."""
        driver = await self._get_driver()
        async with driver.session(database=NEO4J_DATABASE) as session:
            result = await session.run(cypher, params or {})
            records = await result.data()
            return records
    
    async def _execute_read(self, cypher: str, params: dict[str, Any] = None) -> list[dict]:
        """Execute a read transaction and return results."""
        driver = await self._get_driver()
        async with driver.session(database=NEO4J_DATABASE) as session:
            result = await session.run(cypher, params or {})
            records = await result.data()
            return records

    # ─── Schema Initialization ────────────────────────────────────────────────
    
    async def initialize_schema(self):
        """Create indexes and constraints for production performance."""
        constraints = [
            "CREATE CONSTRAINT vendor_id IF NOT EXISTS FOR (v:Vendor) REQUIRE v.id IS UNIQUE",
            "CREATE CONSTRAINT service_id IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT container_id IF NOT EXISTS FOR (c:Container) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT database_id IF NOT EXISTS FOR (d:Database) REQUIRE d.id IS UNIQUE",
            "CREATE CONSTRAINT host_id IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE",
            "CREATE CONSTRAINT user_id IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE",
            "CREATE CONSTRAINT role_id IF NOT EXISTS FOR (r:Role) REQUIRE r.id IS UNIQUE",
        ]
        indexes = [
            "CREATE INDEX vendor_risk_score IF NOT EXISTS FOR (v:Vendor) ON (v.risk_score)",
            "CREATE INDEX node_anomaly_count IF NOT EXISTS FOR (n:Host) ON (n.anomaly_count)",
            "CREATE INDEX threat_timestamp IF NOT EXISTS FOR ()-[r:CONNECTS]-() ON (r.timestamp)",
        ]
        for stmt in constraints + indexes:
            try:
                await self._execute_write(stmt)
            except Exception as e:
                log.warning("Schema statement skipped", statement=stmt[:60], error=str(e))

    # ─── Vendor Node Operations ───────────────────────────────────────────────
    
    async def upsert_vendor(self, vendor_data: dict[str, Any]) -> dict:
        """MERGE-safe upsert of a Vendor node with full property mapping."""
        cypher = """
        MERGE (v:Vendor {id: $id})
        ON CREATE SET
            v.name = $name,
            v.category = $category,
            v.country = $country,
            v.ip_address = $ip_address,
            v.privilege_level = $privilege_level,
            v.risk_score = $risk_score,
            v.anomaly_count = $anomaly_count,
            v.api_key_rotations = $api_key_rotations,
            v.cryptographic_standard = $cryptographic_standard,
            v.data_access_volume_gb = $data_access_volume_gb,
            v.gat_compromise_score = $gat_compromise_score,
            v.historical_trust_score = $historical_trust_score,
            v.timestamp = $timestamp,
            v.created_at = $created_at
        ON MATCH SET
            v.risk_score = $risk_score,
            v.anomaly_count = $anomaly_count,
            v.gat_compromise_score = $gat_compromise_score,
            v.data_access_volume_gb = $data_access_volume_gb,
            v.timestamp = $timestamp
        RETURN v {.*} AS vendor
        """
        params = {
            "id": vendor_data.get("id", ""),
            "name": vendor_data.get("name", ""),
            "category": vendor_data.get("category", ""),
            "country": vendor_data.get("country", ""),
            "ip_address": vendor_data.get("ip_address", "0.0.0.0"),
            "privilege_level": vendor_data.get("privilege_level", 1),
            "risk_score": vendor_data.get("risk_score", 50.0),
            "anomaly_count": vendor_data.get("anomaly_count", 0),
            "api_key_rotations": vendor_data.get("api_key_rotations", 0),
            "cryptographic_standard": vendor_data.get("cryptographic_standard", "TLS1.3"),
            "data_access_volume_gb": vendor_data.get("data_access_volume_gb", 0.0),
            "gat_compromise_score": vendor_data.get("gat_compromise_score", 0.0),
            "historical_trust_score": vendor_data.get("historical_trust_score", 1.0),
            "timestamp": datetime.utcnow().isoformat(),
            "created_at": datetime.utcnow().isoformat(),
        }
        result = await self._execute_write(cypher, params)
        return result[0]["vendor"] if result else {}

    async def get_all_vendors(self) -> list[dict]:
        cypher = """
        MATCH (v:Vendor)
        OPTIONAL MATCH (v)-[r]->(connected)
        WITH v, count(r) AS downstream_degree
        RETURN v {.*, downstream_degree: downstream_degree}
        ORDER BY v.risk_score DESC
        """
        return await self._execute_read(cypher)

    # ─── Service / Container / Host Node Operations ───────────────────────────
    
    async def upsert_service_node(self, node_type: str, node_data: dict[str, Any]) -> dict:
        """Generic MERGE for Service, Container, Database, Host, User, Role nodes."""
        cypher = f"""
        MERGE (n:{node_type} {{id: $id}})
        ON CREATE SET
            n.name = $name,
            n.ip_address = $ip_address,
            n.privilege_level = $privilege_level,
            n.anomaly_count = $anomaly_count,
            n.historical_trust_score = $historical_trust_score,
            n.gat_compromise_score = $gat_compromise_score,
            n.service_tier = $service_tier,
            n.timestamp = $timestamp
        ON MATCH SET
            n.anomaly_count = $anomaly_count,
            n.gat_compromise_score = $gat_compromise_score,
            n.timestamp = $timestamp
        RETURN n {{.*}} AS node
        """
        params = {
            "id": node_data.get("id", ""),
            "name": node_data.get("name", ""),
            "ip_address": node_data.get("ip_address", "0.0.0.0"),
            "privilege_level": node_data.get("privilege_level", 1),
            "anomaly_count": node_data.get("anomaly_count", 0),
            "historical_trust_score": node_data.get("historical_trust_score", 1.0),
            "gat_compromise_score": node_data.get("gat_compromise_score", 0.0),
            "service_tier": node_data.get("service_tier", "standard"),
            "timestamp": datetime.utcnow().isoformat(),
        }
        result = await self._execute_write(cypher, params)
        return result[0]["node"] if result else {}

    # ─── Edge / Relationship Operations ──────────────────────────────────────
    
    async def upsert_relationship(
        self,
        source_id: str,
        source_type: str,
        target_id: str,
        target_type: str,
        rel_type: str,
        properties: dict[str, Any] = None,
    ) -> dict:
        """MERGE-safe directed relationship creation with full property mapping."""
        props = properties or {}
        cypher = f"""
        MATCH (a:{source_type} {{id: $source_id}})
        MATCH (b:{target_type} {{id: $target_id}})
        MERGE (a)-[r:{rel_type}]->(b)
        ON CREATE SET
            r.weight = $weight,
            r.anomaly_flagged = $anomaly_flagged,
            r.timestamp = $timestamp,
            r.created_at = $created_at
        ON MATCH SET
            r.weight = $weight,
            r.anomaly_flagged = $anomaly_flagged,
            r.timestamp = $timestamp
        RETURN r {{.*}} AS relationship,
               a.id AS source_id,
               b.id AS target_id,
               type(r) AS rel_type
        """
        params = {
            "source_id": source_id,
            "target_id": target_id,
            "weight": props.get("weight", 1.0),
            "anomaly_flagged": props.get("anomaly_flagged", False),
            "timestamp": datetime.utcnow().isoformat(),
            "created_at": datetime.utcnow().isoformat(),
        }
        result = await self._execute_write(cypher, params)
        return result[0] if result else {}

    # ─── Graph Topology Query ─────────────────────────────────────────────────
    
    async def get_graph_topology(self) -> dict[str, list[dict]]:
        """
        Extract full graph topology optimized for React Flow ingestion.
        Returns nodes with layout positions and edges with relationship metadata.
        """
        nodes_cypher = """
        MATCH (n)
        WHERE n:Vendor OR n:Service OR n:Container OR n:Database OR n:Host OR n:User OR n:Role
        RETURN
            n.id AS id,
            n.name AS label,
            labels(n)[0] AS type,
            n.ip_address AS ip_address,
            n.service_tier AS service_tier,
            n.privilege_level AS privilege_level,
            n.anomaly_count AS anomaly_count,
            n.gat_compromise_score AS gat_compromise_score,
            n.historical_trust_score AS historical_trust_score,
            n.risk_state AS risk_state
        ORDER BY n.gat_compromise_score DESC
        """
        
        edges_cypher = """
        MATCH (a)-[r]->(b)
        WHERE (a:Vendor OR a:Service OR a:Container OR a:Database OR a:Host OR a:User OR a:Role)
          AND (b:Vendor OR b:Service OR b:Container OR b:Database OR b:Host OR b:User OR b:Role)
        RETURN
            r.id AS id,
            a.id AS source,
            b.id AS target,
            type(r) AS relationship,
            r.weight AS weight,
            r.anomaly_flagged AS anomaly_flagged,
            r.timestamp AS timestamp
        LIMIT 500
        """
        
        nodes = await self._execute_read(nodes_cypher)
        edges = await self._execute_read(edges_cypher)
        
        return {"nodes": nodes, "edges": edges}

    # ─── Splunk Log Ingestion Pipeline ───────────────────────────────────────
    
    async def ingest_splunk_logs(self, log_records: list[dict[str, Any]]) -> dict[str, int]:
        """
        Production Splunk log ingestion pipeline.
        Parses structured log records and maps them into graph mutations
        using MERGE semantics to prevent duplicate topological writes.
        
        Log records must contain: source_id, source_type, target_id, target_type,
        relationship, timestamp, anomaly_flagged, severity.
        """
        created_nodes = 0
        created_edges = 0
        errors = 0
        
        for record in log_records:
            try:
                # Upsert source node
                await self.upsert_service_node(
                    node_type=record.get("source_type", "Host"),
                    node_data={
                        "id": record["source_id"],
                        "name": record.get("source_name", record["source_id"]),
                        "ip_address": record.get("source_ip", "0.0.0.0"),
                        "privilege_level": record.get("privilege_level", 1),
                        "anomaly_count": int(record.get("anomaly_flagged", 0)),
                        "historical_trust_score": record.get("trust_score", 1.0),
                        "gat_compromise_score": 0.0,
                        "service_tier": record.get("service_tier", "standard"),
                    },
                )
                created_nodes += 1
                
                # Upsert target node
                await self.upsert_service_node(
                    node_type=record.get("target_type", "Service"),
                    node_data={
                        "id": record["target_id"],
                        "name": record.get("target_name", record["target_id"]),
                        "ip_address": record.get("target_ip", "0.0.0.0"),
                        "privilege_level": record.get("target_privilege", 1),
                        "anomaly_count": 0,
                        "historical_trust_score": 1.0,
                        "gat_compromise_score": 0.0,
                        "service_tier": record.get("target_tier", "standard"),
                    },
                )
                created_nodes += 1
                
                # Create directed relationship
                await self.upsert_relationship(
                    source_id=record["source_id"],
                    source_type=record.get("source_type", "Host"),
                    target_id=record["target_id"],
                    target_type=record.get("target_type", "Service"),
                    rel_type=record.get("relationship", "CONNECTS"),
                    properties={
                        "weight": record.get("weight", 1.0),
                        "anomaly_flagged": record.get("anomaly_flagged", False),
                        "timestamp": record.get("timestamp", datetime.utcnow().isoformat()),
                    },
                )
                created_edges += 1
                
            except Exception as e:
                log.error("Splunk log ingestion failed for record", record_id=record.get("source_id"), error=str(e))
                errors += 1
        
        log.info(
            "Splunk log ingestion complete",
            created_nodes=created_nodes,
            created_edges=created_edges,
            errors=errors,
        )
        return {"created_nodes": created_nodes, "created_edges": created_edges, "errors": errors}

    # ─── Risk State Update ────────────────────────────────────────────────────
    
    async def update_node_risk_state(self, node_id: str, risk_state: str, gat_score: float) -> bool:
        """Update a node's risk state and GAT compromise score after inference."""
        cypher = """
        MATCH (n {id: $node_id})
        SET n.risk_state = $risk_state,
            n.gat_compromise_score = $gat_score,
            n.last_assessed = $timestamp
        RETURN n.id AS id
        """
        result = await self._execute_write(cypher, {
            "node_id": node_id,
            "risk_state": risk_state,
            "gat_score": gat_score,
            "timestamp": datetime.utcnow().isoformat(),
        })
        return bool(result)

    async def get_downstream_nodes(self, node_id: str, max_depth: int = 3) -> list[dict]:
        """BFS traversal to find all downstream nodes within max_depth hops."""
        cypher = """
        MATCH path = (start {id: $node_id})-[*1..$max_depth]->(downstream)
        WHERE (downstream:Vendor OR downstream:Service OR downstream:Container 
               OR downstream:Database OR downstream:Host OR downstream:User OR downstream:Role)
        RETURN DISTINCT
            downstream.id AS id,
            downstream.name AS name,
            labels(downstream)[0] AS type,
            length(path) AS hop_distance
        ORDER BY hop_distance ASC
        LIMIT 100
        """
        return await self._execute_read(cypher, {"node_id": node_id, "max_depth": max_depth})


# ─── Singleton Instance ───────────────────────────────────────────────────────
neo4j_client = Neo4jClient()
