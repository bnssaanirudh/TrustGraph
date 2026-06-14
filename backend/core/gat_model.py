"""
PyTorch Geometric Graph Attention Network (GAT) — TrustGraph Risk Engine
Production implementation of dual-layer GATConv with multi-head attention
for node-level compromise probability prediction and Blast Radius computation.

Architecture:
  - Input: 5-dimensional node feature vectors
  - Layer 1: GATConv(5 → 64) with 8 attention heads
  - Layer 2: GATConv(512 → 32) with 4 attention heads  
  - Output: Linear(128 → 1) → Sigmoid → compromise probability [0.0, 1.0]

Node Feature Vector: [failed_logins, api_volume, privilege_level, 
                       historical_trust_score, degree_centrality]

Blast Radius Formula:
  Risk(N) = β · Σ(wᵢ · AnomalySeverity) + (1-β) · log(DownstreamDegree + 1)
"""
from __future__ import annotations

import asyncio
import math
import os
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import structlog

log = structlog.get_logger(__name__)

# ─── Conditional PyTorch Import (graceful fallback for non-GPU environments) ──
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch import Tensor
    from torch_geometric.data import Data, Batch
    from torch_geometric.nn import GATConv
    from torch_geometric.utils import to_networkx, degree
    TORCH_AVAILABLE = True
    log.info("PyTorch Geometric initialized", torch_version=torch.__version__)
except ImportError:
    TORCH_AVAILABLE = False
    log.warning("PyTorch Geometric not installed — using numpy fallback inference")

# ─── Node Feature Index Constants ────────────────────────────────────────────
FEAT_FAILED_LOGINS = 0       # Normalized failed login count [0,1]
FEAT_API_VOLUME = 1          # Normalized API request volume [0,1]
FEAT_PRIVILEGE_LEVEL = 2     # IAM privilege level, normalized to [0,1] from [1,5]
FEAT_TRUST_SCORE = 3         # Historical trust score [0,1] (inverted for risk)
FEAT_DEGREE_CENTRALITY = 4   # Normalized graph degree centrality [0,1]

INPUT_DIM = 5
HIDDEN_DIM_1 = 64
HIDDEN_DIM_2 = 32
HEADS_1 = 8
HEADS_2 = 4
DROPOUT = 0.3


# ─── GATNetwork: Dual-Layer Graph Attention Network ──────────────────────────

class GATNetwork(nn.Module):
    """
    Dual-layer Graph Attention Network for node-level risk propagation.
    
    Uses multi-head attention to learn which neighboring nodes contribute
    most to the risk propagation of each node. Outputs a continuous
    compromise probability score for every node in the topology.
    
    Attention Mechanism:
        eᵢⱼ = LeakyReLU(aᵀ · [Wh̃ᵢ || Wh̃ⱼ])
        αᵢⱼ = softmax_j(eᵢⱼ)  (normalized over neighborhood N(i))
        h'ᵢ = σ(Σⱼ∈N(i) αᵢⱼ · Wh̃ⱼ)
    """
    
    def __init__(
        self,
        in_channels: int = INPUT_DIM,
        hidden_channels_1: int = HIDDEN_DIM_1,
        hidden_channels_2: int = HIDDEN_DIM_2,
        heads_1: int = HEADS_1,
        heads_2: int = HEADS_2,
        dropout: float = DROPOUT,
    ):
        super().__init__()
        self.dropout = dropout
        
        # Layer 1: Multi-head GAT — expands feature space
        # Output: (N, hidden_channels_1 * heads_1) = (N, 64*8) = (N, 512)
        self.gat_layer_1 = GATConv(
            in_channels=in_channels,
            out_channels=hidden_channels_1,
            heads=heads_1,
            dropout=dropout,
            add_self_loops=True,
            bias=True,
        )
        
        # Layer 2: Multi-head GAT — aggregates risk signals
        # Input: (N, 512), Output: (N, hidden_channels_2 * heads_2) = (N, 128)
        self.gat_layer_2 = GATConv(
            in_channels=hidden_channels_1 * heads_1,
            out_channels=hidden_channels_2,
            heads=heads_2,
            dropout=dropout,
            add_self_loops=True,
            bias=True,
        )
        
        # Output projection: Maps 128-dim attention vectors → compromise probability
        self.output_projection = nn.Linear(hidden_channels_2 * heads_2, 1)
        
        # Batch normalization for training stability
        self.bn1 = nn.BatchNorm1d(hidden_channels_1 * heads_1)
        self.bn2 = nn.BatchNorm1d(hidden_channels_2 * heads_2)
        
        # Weight initialization
        self._init_weights()
    
    def _init_weights(self):
        """Kaiming uniform initialization for risk-sensitive convergence."""
        nn.init.kaiming_uniform_(self.output_projection.weight, nonlinearity="sigmoid")
        nn.init.constant_(self.output_projection.bias, -0.5)  # Bias toward safe (low risk)
    
    def forward(self, x: Tensor, edge_index: Tensor, return_attention: bool = False):
        """
        Forward pass through dual GAT layers.
        
        Args:
            x: Node feature matrix (N, 5) — [failed_logins, api_volume, privilege,
                                              trust_score, degree_centrality]
            edge_index: COO format edge indices (2, E) — directed edges [source, target]
            return_attention: If True, returns (output, attention_weights_layer1, attention_weights_layer2)
        
        Returns:
            compromise_scores: (N, 1) sigmoid-normalized risk probabilities [0, 1]
        """
        # ── Layer 1: Attend over direct neighbors ────────────────────────────
        if return_attention:
            x1, (edge_idx_1, alpha_1) = self.gat_layer_1(x, edge_index, return_attention_weights=True)
        else:
            x1 = self.gat_layer_1(x, edge_index)
        
        x1 = self.bn1(x1)
        x1 = F.elu(x1)                              # ELU: smoother than ReLU for risk signals
        x1 = F.dropout(x1, p=self.dropout, training=self.training)
        
        # ── Layer 2: Attend over 2-hop neighborhood ───────────────────────────
        if return_attention:
            x2, (edge_idx_2, alpha_2) = self.gat_layer_2(x1, edge_index, return_attention_weights=True)
        else:
            x2 = self.gat_layer_2(x1, edge_index)
        
        x2 = self.bn2(x2)
        x2 = F.elu(x2)
        x2 = F.dropout(x2, p=self.dropout, training=self.training)
        
        # ── Output: Compromise Probability ───────────────────────────────────
        logits = self.output_projection(x2)          # (N, 1) raw logits
        compromise_scores = torch.sigmoid(logits)    # (N, 1) probabilities [0, 1]
        
        if return_attention:
            return compromise_scores, alpha_1, alpha_2
        return compromise_scores


# ─── Blast Radius Calculator ─────────────────────────────────────────────────

def compute_blast_radius(
    node_id: str,
    anomaly_severities: list[float],
    edge_weights: list[float],
    downstream_degree: int,
    beta: float = 0.7,
) -> float:
    """
    Blast Radius Equation (native tensor computation):
    
        Risk(N) = β · Σ(wᵢ · AnomalySeverity_i) + (1-β) · log(DownstreamDegree + 1)
    
    Args:
        node_id: Node identifier for logging
        anomaly_severities: List of anomaly severity scores for incident edges [0.0, 1.0]
        edge_weights: Corresponding edge weights (GAT attention coefficients)
        downstream_degree: Number of downstream nodes reachable from this node
        beta: Blend weight between local anomaly severity and structural exposure
              β=1.0: Pure anomaly-based risk, β=0.0: Pure structural risk
    
    Returns:
        blast_radius: Normalized risk score [0.0, 1.0]
    """
    if TORCH_AVAILABLE:
        # Use tensors for batch efficiency
        severities = torch.tensor(anomaly_severities, dtype=torch.float32)
        weights = torch.tensor(edge_weights, dtype=torch.float32)
        
        # Weighted anomaly component: Σ(wᵢ · Severityᵢ)
        weighted_anomaly_sum = torch.dot(weights, severities).item()
        
        # Structural exposure component: log(DownstreamDegree + 1)
        structural_exposure = math.log(downstream_degree + 1)
        
        # Blend via beta weight
        raw_risk = beta * weighted_anomaly_sum + (1.0 - beta) * structural_exposure
        
        # Normalize to [0, 1] using sigmoid compression
        blast_radius = 1.0 / (1.0 + math.exp(-raw_risk + 2.0))
    else:
        # NumPy fallback
        if anomaly_severities and edge_weights:
            sev_arr = np.array(anomaly_severities)
            wt_arr = np.array(edge_weights)
            weighted_anomaly_sum = float(np.dot(wt_arr, sev_arr))
        else:
            weighted_anomaly_sum = 0.0
        
        structural_exposure = math.log(downstream_degree + 1)
        raw_risk = beta * weighted_anomaly_sum + (1.0 - beta) * structural_exposure
        blast_radius = 1.0 / (1.0 + math.exp(-raw_risk + 2.0))
    
    log.debug(
        "Blast radius computed",
        node_id=node_id,
        weighted_anomaly=round(weighted_anomaly_sum if anomaly_severities else 0.0, 4),
        structural_exposure=round(structural_exposure if 'structural_exposure' in dir() else math.log(downstream_degree+1), 4),
        blast_radius=round(blast_radius, 4),
        beta=beta,
    )
    return float(blast_radius)


# ─── GAT Inference Engine ─────────────────────────────────────────────────────

@dataclass
class GATInferenceResult:
    """Complete GAT inference output for a graph topology."""
    node_ids: list[str]
    compromise_probabilities: list[float]
    blast_radius_scores: list[float]
    attention_weights_l1: list[list[float]] = field(default_factory=list)
    attention_weights_l2: list[list[float]] = field(default_factory=list)
    downstream_counts: list[int] = field(default_factory=list)
    global_blast_radius: float = 0.0
    model_version: str = "gat_v2.0_dual_head"


class GATInferenceEngine:
    """
    Production inference engine wrapping GATNetwork.
    Handles graph construction from API payloads, model loading,
    and result extraction.
    """
    
    _instance: Optional["GATInferenceEngine"] = None
    _model: Optional[GATNetwork] = None
    
    def __init__(self):
        self.device = torch.device("cuda" if TORCH_AVAILABLE and torch.cuda.is_available() else "cpu")
        self._model = None
        self._load_or_init_model()
    
    def _load_or_init_model(self):
        """Load pre-trained weights or initialize a fresh model."""
        if not TORCH_AVAILABLE:
            log.warning("PyTorch unavailable — GAT using numpy fallback")
            return
        
        model_path = os.getenv("GAT_MODEL_PATH", "models/gat_trustgraph.pt")
        
        self._model = GATNetwork(
            in_channels=INPUT_DIM,
            hidden_channels_1=HIDDEN_DIM_1,
            hidden_channels_2=HIDDEN_DIM_2,
            heads_1=HEADS_1,
            heads_2=HEADS_2,
            dropout=DROPOUT,
        ).to(self.device)
        
        if os.path.exists(model_path):
            try:
                state_dict = torch.load(model_path, map_location=self.device, weights_only=True)
                self._model.load_state_dict(state_dict)
                log.info("GAT model weights loaded from disk", path=model_path)
            except Exception as e:
                log.warning("GAT weight load failed — using initialized weights", error=str(e))
        else:
            log.info("No saved GAT weights — using freshly initialized model")
        
        self._model.eval()
    
    def _build_graph_tensors(
        self,
        node_features: list[dict],
        edges: list[dict],
    ) -> tuple[Tensor, Tensor]:
        """
        Convert API node/edge dictionaries to PyTorch Geometric tensors.
        
        Feature normalization:
        - failed_logins: divide by 100 (cap at 1.0)
        - api_volume: log-normalize then divide by 10
        - privilege_level: (level - 1) / 4  → [0,1]
        - historical_trust_score: already [0,1]
        - degree_centrality: divide by max degree (or 1.0)
        """
        if not TORCH_AVAILABLE:
            return None, None
        
        n = len(node_features)
        x = torch.zeros((n, INPUT_DIM), dtype=torch.float32)
        
        for i, nf in enumerate(node_features):
            x[i, FEAT_FAILED_LOGINS] = min(nf.get("failed_logins", 0) / 100.0, 1.0)
            x[i, FEAT_API_VOLUME] = min(math.log1p(nf.get("api_volume", 0)) / 10.0, 1.0)
            x[i, FEAT_PRIVILEGE_LEVEL] = (nf.get("privilege_level", 1) - 1) / 4.0
            x[i, FEAT_TRUST_SCORE] = 1.0 - nf.get("historical_trust_score", 1.0)  # Invert: low trust = high risk
            x[i, FEAT_DEGREE_CENTRALITY] = min(nf.get("degree_centrality", 0) / 10.0, 1.0)
        
        # Build edge_index tensor (COO format)
        if edges:
            # Map node IDs to indices
            id_to_idx = {nf.get("id", str(i)): i for i, nf in enumerate(node_features)}
            
            edge_src = []
            edge_dst = []
            for edge in edges:
                src_idx = id_to_idx.get(edge.get("source", ""), -1)
                dst_idx = id_to_idx.get(edge.get("target", ""), -1)
                if src_idx >= 0 and dst_idx >= 0:
                    edge_src.append(src_idx)
                    edge_dst.append(dst_idx)
            
            if edge_src:
                edge_index = torch.tensor([edge_src, edge_dst], dtype=torch.long)
            else:
                # Self-loops only if no edges
                edge_index = torch.stack([torch.arange(n), torch.arange(n)])
        else:
            edge_index = torch.stack([torch.arange(n), torch.arange(n)])
        
        return x.to(self.device), edge_index.to(self.device)
    
    async def run_inference(
        self,
        node_features: list[dict],
        edges: list[dict],
        beta: float = 0.7,
    ) -> GATInferenceResult:
        """
        Execute full GAT inference pass over a graph topology.
        
        Args:
            node_features: List of node dicts with feature fields
            edges: List of edge dicts with source/target fields
            beta: Blast radius beta weight
        
        Returns:
            GATInferenceResult with per-node risk vectors
        """
        node_ids = [nf.get("id", str(i)) for i, nf in enumerate(node_features)]
        
        if not TORCH_AVAILABLE or not node_features:
            # Numpy fallback: simple weighted scoring
            return self._numpy_fallback_inference(node_ids, node_features, edges, beta)
        
        x, edge_index = self._build_graph_tensors(node_features, edges)
        
        # Run GAT forward pass in inference mode
        with torch.no_grad():
            compromise_scores, alpha_1, alpha_2 = self._model(
                x, edge_index, return_attention=True
            )
        
        # Extract compromise probabilities
        probs = compromise_scores.squeeze(-1).cpu().numpy().tolist()
        
        # Extract attention weights (mean across heads for interpretability)
        # alpha_1 shape: (E * heads_1,) — attention per edge per head
        alpha_1_mean = alpha_1.mean(dim=1).cpu().numpy() if alpha_1.dim() > 1 else alpha_1.cpu().numpy()
        alpha_2_mean = alpha_2.mean(dim=1).cpu().numpy() if alpha_2.dim() > 1 else alpha_2.cpu().numpy()
        
        # Compute downstream degrees for blast radius
        downstream_counts = []
        blast_radii = []
        id_to_idx = {nf.get("id", str(i)): i for i, nf in enumerate(node_features)}
        
        for i, nf in enumerate(node_features):
            # Count downstream nodes (targets from this node)
            downstream = sum(
                1 for e in edges
                if e.get("source") == nf.get("id")
            )
            downstream_counts.append(downstream)
            
            # Gather anomaly severities and weights for incident edges
            incident_edges = [
                e for e in edges
                if e.get("source") == nf.get("id") or e.get("target") == nf.get("id")
            ]
            
            # Map anomaly_flagged to severity score
            sev_scores = [
                0.85 if e.get("anomaly_flagged") else 0.1
                for e in incident_edges
            ]
            
            # Use normalized edge weights or uniform
            edge_wts = [e.get("weight", 1.0) for e in incident_edges]
            if edge_wts:
                max_wt = max(edge_wts)
                edge_wts = [w / max_wt for w in edge_wts]
            
            blast = compute_blast_radius(
                node_id=nf.get("id", str(i)),
                anomaly_severities=sev_scores,
                edge_weights=edge_wts if edge_wts else [1.0],
                downstream_degree=downstream,
                beta=beta,
            )
            blast_radii.append(blast)
        
        # Global blast radius: area-weighted average
        global_blast = float(np.mean(blast_radii)) if blast_radii else 0.0
        
        # Assign attention weights per node (average of incident edge attentions)
        n_edges = len(edges)
        attn_l1_per_node = [[0.0] for _ in range(len(node_ids))]
        attn_l2_per_node = [[0.0] for _ in range(len(node_ids))]
        
        if len(alpha_1_mean) > 0 and n_edges > 0:
            edges_per_node = max(1, len(alpha_1_mean) // max(len(node_ids), 1))
            for i in range(len(node_ids)):
                start = i * edges_per_node
                end = min(start + edges_per_node, len(alpha_1_mean))
                if start < len(alpha_1_mean):
                    attn_l1_per_node[i] = alpha_1_mean[start:end].tolist()
                    attn_l2_per_node[i] = alpha_2_mean[start:min(end, len(alpha_2_mean))].tolist()
        
        log.info(
            "GAT inference complete",
            n_nodes=len(node_ids),
            n_edges=len(edges),
            global_blast_radius=round(global_blast, 4),
            high_risk_nodes=sum(1 for p in probs if p > 0.7),
        )
        
        return GATInferenceResult(
            node_ids=node_ids,
            compromise_probabilities=probs,
            blast_radius_scores=blast_radii,
            attention_weights_l1=attn_l1_per_node,
            attention_weights_l2=attn_l2_per_node,
            downstream_counts=downstream_counts,
            global_blast_radius=global_blast,
        )
    
    def _numpy_fallback_inference(
        self,
        node_ids: list[str],
        node_features: list[dict],
        edges: list[dict],
        beta: float,
    ) -> GATInferenceResult:
        """
        Deterministic numpy-based risk scoring fallback when PyTorch is unavailable.
        Uses weighted linear combination of node features to estimate risk.
        """
        probs = []
        blast_radii = []
        
        for nf in node_features:
            # Normalized feature extraction
            f_failed = min(nf.get("failed_logins", 0) / 100.0, 1.0)
            f_api = min(math.log1p(nf.get("api_volume", 0)) / 10.0, 1.0)
            f_priv = (nf.get("privilege_level", 1) - 1) / 4.0
            f_trust = 1.0 - nf.get("historical_trust_score", 1.0)
            f_degree = min(nf.get("degree_centrality", 0) / 10.0, 1.0)
            
            # Linear risk estimate with domain-expert weights
            risk = (
                0.30 * f_failed +
                0.20 * f_api +
                0.25 * f_priv +
                0.15 * f_trust +
                0.10 * f_degree
            )
            probs.append(float(np.clip(risk, 0.0, 1.0)))
            
            # Simplified blast radius
            downstream = sum(1 for e in edges if e.get("source") == nf.get("id"))
            blast = compute_blast_radius(
                node_id=nf.get("id", ""),
                anomaly_severities=[risk],
                edge_weights=[1.0],
                downstream_degree=downstream,
                beta=beta,
            )
            blast_radii.append(blast)
        
        return GATInferenceResult(
            node_ids=node_ids,
            compromise_probabilities=probs,
            blast_radius_scores=blast_radii,
            downstream_counts=[
                sum(1 for e in edges if e.get("source") == nf.get("id"))
                for nf in node_features
            ],
            global_blast_radius=float(np.mean(blast_radii)) if blast_radii else 0.0,
        )


# ─── Singleton Instance ───────────────────────────────────────────────────────
_gat_engine: Optional[GATInferenceEngine] = None


def get_gat_engine() -> GATInferenceEngine:
    """Lazy singleton accessor for the GAT inference engine."""
    global _gat_engine
    if _gat_engine is None:
        _gat_engine = GATInferenceEngine()
    return _gat_engine
