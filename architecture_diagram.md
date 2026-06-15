# TrustGraph Architecture Diagram

The system architecture consists of a real-time data ingestion layer, a graph database mapping layer, a GNN risk propagation engine, an agentic decision/hunt loop, and a user visualization dashboard.

```mermaid
graph TB
    subgraph Data Ingestion & Querying
        A[Splunk Enterprise / Cloud] <-->|Telemetry logs| B[Splunk MCP Server]
    end

    subgraph Backend Core (FastAPI)
        B <-->|MCP Protocol| C[FastAPI Main Application]
        C -->|Idempotent writes| D[(Neo4j Graph Database)]
        D -->|Read graph state| E[PyTorch Geometric GAT Engine]
        E -->|Write risk scores| D
        C <-->|Orchestrates Threat Hunt| F[LangGraph CARAG Pipeline]
        F -->|Generate SPL| B
    end

    subgraph CARAG Pipeline Detail
        F1[Planner Node] --> F2[Retriever Node]
        F2 --> F3{Evaluator Node}
        F3 -->|Score < 0.85| F4[Refiner Node]
        F4 --> F2
        F3 -->|Score >= 0.85| F5[Mitigator Node]
    end

    subgraph Frontend Dashboard (Next.js)
        G[Next.js App Router UI] <-->|Fetch API Data / REST| C
        G1[ReactFlow Graph View] <--> G
        G2[Operations Telemetry] <--> G
    end

    classDef database fill:#1d2a44,stroke:#3b82f6,stroke-width:2px,color:#fff;
    classDef model fill:#2d1b4e,stroke:#8b5cf6,stroke-width:2px,color:#fff;
    classDef web fill:#0a1c2a,stroke:#10b981,stroke-width:2px,color:#fff;
    
    class D database;
    class E model;
    class G,G1,G2 web;
```

### Architecture Component Layers:
1. **Splunk MCP (Model Context Protocol)**: Exposes search and log retrieval capabilities to the agent, translating threat hunting intents into optimized Splunk Processing Language (SPL) queries.
2. **Neo4j database**: Stores the network topology (Service, Host, Container, Database, User nodes and their interactions) to maintain a stateful map of the infrastructure.
3. **PyTorch Geometric GAT Engine**: Runs dual-layer Graph Attention Network (`GATConv`) layers to evaluate relative threat propagation probabilities across neighbors using attention coefficients.
4. **LangGraph CARAG Pipeline**: Orchestrates an iterative self-correction loop where generated queries are scored for relevancy. If details are missing or target coordinates are off, the agent refines and re-executes.
5. **Next.js Dashboard**: Renders the dynamic topology using ReactFlow and offers controls for exploring threat nodes, investigating active breach status, and executing manual queries.
