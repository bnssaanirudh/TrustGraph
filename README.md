# TrustGraph: Agentic Third-Party Risk & Threat Hunting Platform

TrustGraph is an advanced security platform designed to detect, analyze, and visualize complex threats originating from third-party vendor integrations. By combining the power of graph databases, real-time SIEM integration, and autonomous AI agents, TrustGraph provides unprecedented visibility into your attack surface and automated threat hunting capabilities.

## The Problem

Modern organizations rely heavily on an interconnected web of third-party vendors, APIs, and external services. This interconnectedness drastically expands the attack surface. When a trusted third-party is compromised, attackers can leverage those legitimate connections to move laterally, escalate privileges, and exfiltrate data. 

Traditional security tools and SIEMs operate in silos. They generate static alerts based on isolated events, making it incredibly difficult for security operations center (SOC) teams to:
1. Trace the origin of an attack through multiple hops.
2. Understand the "blast radius" of a compromised vendor.
3. Keep up with the manual effort required to write complex queries across disparate data sources.

The result is alert fatigue, delayed incident response, and hidden attack paths that remain undetected until it is too late.

## The Solution

TrustGraph fundamentally changes how security teams approach third-party risk and threat hunting. Instead of looking at flat logs, TrustGraph models your entire infrastructure—vendors, hosts, containers, users, and databases—as a dynamic **Graph Topology**. 

Coupled with an **Agentic AI Pipeline (CARAG)**, TrustGraph allows analysts to perform complex, multi-stage threat hunts using plain natural language. 

### How It Works:
1. **Agentic Translation**: Analysts express their intent in natural language (e.g., *"Detect lateral movement from VendorX to the customer database"*). The AI translates this intent into optimized SPL (Search Processing Language) queries.
2. **Real-time Splunk Integration**: TrustGraph queries your Splunk instance via the Model Context Protocol (MCP) to retrieve relevant telemetry data.
3. **Graph Correlation**: The ingested logs are mapped onto a Neo4j graph database, establishing relationships (edges) between entities (nodes).
4. **Risk Scoring**: TrustGraph analyzes the graph topology to calculate anomaly scores, assess the potential blast radius, and prioritize critical threats based on their proximity to crown-jewel assets.

## Key Features

- **Natural Language Threat Hunting**: Query complex attack paths without needing to be an SPL expert. The AI handles query construction and refinement.
- **Graph-Based Visualization**: See exactly how vendors connect to your internal services. Visually trace lateral movement and privilege escalation paths.
- **Automated SIEM Ingestion**: Seamless integration with Splunk via a dedicated MCP Server daemon, ensuring your graph is always up-to-date with the latest telemetry.
- **Resilient Architecture**: Built-in fallback mechanisms ensure that if API connections fail, the system can gracefully pivot to local seed data to maintain analytical capabilities.
- **Dynamic Risk Scoring**: Risk isn't just about the event itself; it's about *where* it happens in the network. TrustGraph factors in topological importance to prioritize alerts.

## Architecture

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

## Getting Started

### Prerequisites
- Python 3.10+
- Neo4j Database (Local or AuraDB)
- Splunk Enterprise or Splunk Cloud (with MCP Server configured)

### Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/bnssaanirudh/TrustGraph.git
   cd TrustGraph
   ```

2. **Configure Environment Variables**:
   Set up your connection strings for Neo4j and Splunk in your environment or `.env` file.
   ```bash
   SPLUNK_MCP_HOST=localhost
   SPLUNK_MCP_PORT=8080
   SPLUNK_INDEX=trustgraph_logs
   ```

3. **Install Backend Dependencies**:
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

4. **Run the MCP Server and FastAPI App**:
   ```bash
   # Terminal 1: Start the Splunk MCP Server daemon
   python splunk_mcp_server.py

   # Terminal 2: Start the FastAPI backend
   uvicorn main:app --reload
   ```

5. **Start the Frontend**:
   Navigate to the `frontend` directory, install dependencies, and start the development server according to the specific frontend framework used.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request or open an Issue for any bugs or feature requests.

## License
This project is licensed under the MIT License.
