"""
Graph Service - Fraud Ring Detection and Visualization

Provides link analysis capabilities for:
- Fraud ring detection (shared device fingerprints, IPs, accounts)
- Network visualization data for Cytoscape.js frontend
- Relationship scoring and clustering

Architecture:
- Graph-based fraud pattern detection
- Real-time relationship building
- REST API for frontend visualization

Reference: Gap Analysis - Graph Visualization (MEDIUM priority)
"""

import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum
import hashlib
import json

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel

from app.dependencies import get_current_user
from app.models import User

logger = logging.getLogger("sentineliq.graph")

router = APIRouter(prefix="/api/v1/graph", tags=["graph"])


class NodeType(str, Enum):
    """Types of nodes in the fraud graph."""
    USER = "user"
    DEVICE = "device"
    IP_ADDRESS = "ip"
    EMAIL = "email"
    PHONE = "phone"
    PAYMENT_METHOD = "payment"
    SESSION = "session"
    TRANSACTION = "transaction"


class EdgeType(str, Enum):
    """Types of edges (relationships) in the fraud graph."""
    OWNS = "owns"  # User owns device/email/phone
    USED_FROM = "used_from"  # Session from IP
    LINKED_TO = "linked_to"  # Generic link
    TRANSACTED = "transacted"  # User made transaction
    SHARES_DEVICE = "shares_device"  # Multiple users, same device
    SHARES_IP = "shares_ip"  # Multiple users, same IP
    SHARES_PAYMENT = "shares_payment"  # Multiple users, same payment method


@dataclass
class GraphNode:
    """Node in the fraud graph."""
    id: str
    type: NodeType
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    
    def to_cytoscape(self) -> Dict[str, Any]:
        """Convert to Cytoscape.js format."""
        return {
            "data": {
                "id": self.id,
                "label": self.label,
                "type": self.type.value,
                "risk_score": self.risk_score,
                **self.properties
            },
            "classes": f"{self.type.value} risk-{self._risk_class()}"
        }
    
    def _risk_class(self) -> str:
        """Get risk class for styling."""
        if self.risk_score >= 0.8:
            return "critical"
        elif self.risk_score >= 0.6:
            return "high"
        elif self.risk_score >= 0.4:
            return "medium"
        return "low"


@dataclass
class GraphEdge:
    """Edge in the fraud graph."""
    source: str
    target: str
    type: EdgeType
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_cytoscape(self) -> Dict[str, Any]:
        """Convert to Cytoscape.js format."""
        return {
            "data": {
                "id": f"{self.source}-{self.target}",
                "source": self.source,
                "target": self.target,
                "type": self.type.value,
                "weight": self.weight,
                **self.properties
            },
            "classes": self.type.value
        }


class FraudGraph:
    """
    In-memory fraud graph for relationship analysis.
    
    In production, this would be backed by:
    - Neo4j for persistent graph storage
    - Redis for real-time relationship cache
    """
    
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.adjacency: Dict[str, Set[str]] = defaultdict(set)
    
    def add_node(self, node: GraphNode) -> GraphNode:
        """Add or update a node."""
        if node.id in self.nodes:
            # Update existing node
            existing = self.nodes[node.id]
            existing.last_seen = datetime.utcnow()
            existing.properties.update(node.properties)
            if node.risk_score > existing.risk_score:
                existing.risk_score = node.risk_score
            return existing
        
        self.nodes[node.id] = node
        return node
    
    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        """Add an edge."""
        self.edges.append(edge)
        self.adjacency[edge.source].add(edge.target)
        self.adjacency[edge.target].add(edge.source)
        return edge
    
    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get a node by ID."""
        return self.nodes.get(node_id)
    
    def get_neighbors(self, node_id: str) -> List[GraphNode]:
        """Get neighboring nodes."""
        neighbor_ids = self.adjacency.get(node_id, set())
        return [self.nodes[nid] for nid in neighbor_ids if nid in self.nodes]
    
    def get_edges_for_node(self, node_id: str) -> List[GraphEdge]:
        """Get all edges connected to a node."""
        return [
            e for e in self.edges
            if e.source == node_id or e.target == node_id
        ]
    
    def get_subgraph(
        self,
        center_node_id: str,
        depth: int = 2,
        max_nodes: int = 100
    ) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """
        Get subgraph centered on a node.
        
        Uses BFS to explore relationships up to specified depth.
        """
        if center_node_id not in self.nodes:
            return [], []
        
        visited: Set[str] = set()
        queue = [(center_node_id, 0)]
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        
        while queue and len(nodes) < max_nodes:
            current_id, current_depth = queue.pop(0)
            
            if current_id in visited:
                continue
            
            visited.add(current_id)
            
            if current_id in self.nodes:
                nodes.append(self.nodes[current_id])
            
            if current_depth < depth:
                for neighbor_id in self.adjacency.get(current_id, set()):
                    if neighbor_id not in visited:
                        queue.append((neighbor_id, current_depth + 1))
        
        # Get edges between visited nodes
        visited_set = visited
        for edge in self.edges:
            if edge.source in visited_set and edge.target in visited_set:
                edges.append(edge)
        
        return nodes, edges
    
    def find_fraud_rings(
        self,
        min_size: int = 3,
        min_shared_attributes: int = 2
    ) -> List[Dict[str, Any]]:
        """
        Detect potential fraud rings.
        
        A fraud ring is a cluster of users sharing multiple
        identifiers (device, IP, payment method, etc.)
        """
        # Find user nodes
        user_nodes = [
            n for n in self.nodes.values()
            if n.type == NodeType.USER
        ]
        
        # Build user-to-shared-attributes map
        user_shared: Dict[str, Set[str]] = defaultdict(set)
        
        for edge in self.edges:
            if edge.type in [
                EdgeType.SHARES_DEVICE,
                EdgeType.SHARES_IP,
                EdgeType.SHARES_PAYMENT
            ]:
                user_shared[edge.source].add(edge.target)
                user_shared[edge.target].add(edge.source)
        
        # Find connected components (potential rings)
        visited: Set[str] = set()
        rings: List[Dict[str, Any]] = []
        
        for user in user_nodes:
            if user.id in visited:
                continue
            
            # BFS to find connected users
            component: Set[str] = set()
            queue = [user.id]
            
            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                
                visited.add(current)
                component.add(current)
                
                for connected in user_shared.get(current, set()):
                    if connected not in visited:
                        queue.append(connected)
            
            # Check if this is a potential fraud ring
            if len(component) >= min_size:
                # Calculate shared attributes
                shared_devices = set()
                shared_ips = set()
                shared_payments = set()
                
                for uid in component:
                    for edge in self.get_edges_for_node(uid):
                        if edge.type == EdgeType.OWNS:
                            target_node = self.get_node(edge.target)
                            if target_node:
                                if target_node.type == NodeType.DEVICE:
                                    shared_devices.add(edge.target)
                                elif target_node.type == NodeType.PAYMENT_METHOD:
                                    shared_payments.add(edge.target)
                        elif edge.type == EdgeType.USED_FROM:
                            shared_ips.add(edge.target)
                
                # Calculate risk score for the ring
                risk_score = self._calculate_ring_risk(
                    len(component),
                    len(shared_devices),
                    len(shared_ips),
                    len(shared_payments)
                )
                
                rings.append({
                    "id": hashlib.md5(
                        json.dumps(sorted(component)).encode()
                    ).hexdigest()[:8],
                    "users": list(component),
                    "size": len(component),
                    "shared_devices": len(shared_devices),
                    "shared_ips": len(shared_ips),
                    "shared_payments": len(shared_payments),
                    "risk_score": risk_score,
                    "detected_at": datetime.utcnow().isoformat()
                })
        
        # Sort by risk score
        return sorted(rings, key=lambda r: r["risk_score"], reverse=True)
    
    def _calculate_ring_risk(
        self,
        user_count: int,
        device_count: int,
        ip_count: int,
        payment_count: int
    ) -> float:
        """Calculate fraud ring risk score."""
        # Base score from user count
        base_score = min(user_count / 10, 0.5)
        
        # Sharing penalties
        if device_count > 0 and user_count > device_count:
            # More users than devices = suspicious
            base_score += 0.2 * (user_count / device_count - 1)
        
        if payment_count > 0:
            # Shared payment methods are very suspicious
            base_score += 0.3 * min(payment_count / user_count, 1)
        
        return min(base_score, 1.0)


# Global graph instance
_fraud_graph: Optional[FraudGraph] = None


def get_fraud_graph() -> FraudGraph:
    """Get or create fraud graph singleton."""
    global _fraud_graph
    if _fraud_graph is None:
        _fraud_graph = FraudGraph()
        _seed_demo_data(_fraud_graph)
    return _fraud_graph


def _seed_demo_data(graph: FraudGraph):
    """Seed demo data for visualization."""
    # Create a suspicious ring
    for i in range(1, 6):
        user_id = f"user_{i:03d}"
        graph.add_node(GraphNode(
            id=user_id,
            type=NodeType.USER,
            label=f"User {i}",
            risk_score=0.3 + (i * 0.1),
            properties={"email": f"user{i}@example.com"}
        ))
    
    # Shared device
    device_id = "device_shared_001"
    graph.add_node(GraphNode(
        id=device_id,
        type=NodeType.DEVICE,
        label="Shared Device",
        risk_score=0.8,
        properties={"fingerprint": "abc123..."}
    ))
    
    # Shared IP
    ip_id = "ip_192.168.1.100"
    graph.add_node(GraphNode(
        id=ip_id,
        type=NodeType.IP_ADDRESS,
        label="192.168.1.100",
        risk_score=0.6,
        properties={"country": "US", "vpn": True}
    ))
    
    # Connect users to shared resources
    for i in range(1, 6):
        user_id = f"user_{i:03d}"
        
        graph.add_edge(GraphEdge(
            source=user_id,
            target=device_id,
            type=EdgeType.OWNS,
            weight=1.0
        ))
        
        if i <= 3:  # First 3 users share IP
            graph.add_edge(GraphEdge(
                source=user_id,
                target=ip_id,
                type=EdgeType.USED_FROM,
                weight=0.8
            ))
    
    # Add some normal users
    for i in range(6, 10):
        user_id = f"user_{i:03d}"
        graph.add_node(GraphNode(
            id=user_id,
            type=NodeType.USER,
            label=f"User {i}",
            risk_score=0.1,
            properties={"email": f"user{i}@example.com"}
        ))
        
        # Each has unique device
        dev_id = f"device_{i:03d}"
        graph.add_node(GraphNode(
            id=dev_id,
            type=NodeType.DEVICE,
            label=f"Device {i}",
            risk_score=0.1
        ))
        
        graph.add_edge(GraphEdge(
            source=user_id,
            target=dev_id,
            type=EdgeType.OWNS
        ))


# === API Models ===

class GraphQueryParams(BaseModel):
    """Query parameters for graph API."""
    center_node: Optional[str] = None
    depth: int = 2
    max_nodes: int = 100


class CytoscapeGraphResponse(BaseModel):
    """Cytoscape.js compatible response."""
    elements: Dict[str, List[Dict[str, Any]]]
    stats: Dict[str, Any]


class FraudRingResponse(BaseModel):
    """Fraud ring detection response."""
    rings: List[Dict[str, Any]]
    total_count: int
    high_risk_count: int


# === API Routes ===

@router.get("/network", response_model=CytoscapeGraphResponse)
async def get_network_graph(
    center_node: Optional[str] = Query(None, description="Center node ID"),
    depth: int = Query(2, ge=1, le=5, description="Exploration depth"),
    max_nodes: int = Query(100, ge=10, le=500, description="Maximum nodes"),
    current_user: User = Depends(get_current_user)
):
    """
    Get network graph for visualization.
    
    Returns Cytoscape.js compatible format.
    """
    graph = get_fraud_graph()
    
    if center_node:
        nodes, edges = graph.get_subgraph(center_node, depth, max_nodes)
    else:
        # Return entire graph (limited)
        nodes = list(graph.nodes.values())[:max_nodes]
        edges = graph.edges
    
    # Convert to Cytoscape format
    cytoscape_nodes = [n.to_cytoscape() for n in nodes]
    cytoscape_edges = [e.to_cytoscape() for e in edges]
    
    # Ensure edges only reference existing nodes
    node_ids = {n["data"]["id"] for n in cytoscape_nodes}
    cytoscape_edges = [
        e for e in cytoscape_edges
        if e["data"]["source"] in node_ids and e["data"]["target"] in node_ids
    ]
    
    return {
        "elements": {
            "nodes": cytoscape_nodes,
            "edges": cytoscape_edges
        },
        "stats": {
            "total_nodes": len(cytoscape_nodes),
            "total_edges": len(cytoscape_edges),
            "node_types": _count_by_type(nodes),
            "generated_at": datetime.utcnow().isoformat()
        }
    }


@router.get("/fraud-rings", response_model=FraudRingResponse)
async def detect_fraud_rings(
    min_size: int = Query(3, ge=2, description="Minimum ring size"),
    current_user: User = Depends(get_current_user)
):
    """
    Detect potential fraud rings.
    
    Returns clusters of users sharing suspicious attributes.
    """
    graph = get_fraud_graph()
    rings = graph.find_fraud_rings(min_size=min_size)
    
    high_risk = [r for r in rings if r["risk_score"] >= 0.7]
    
    return {
        "rings": rings,
        "total_count": len(rings),
        "high_risk_count": len(high_risk)
    }


@router.get("/node/{node_id}")
async def get_node_details(
    node_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get details for a specific node."""
    graph = get_fraud_graph()
    node = graph.get_node(node_id)
    
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    
    neighbors = graph.get_neighbors(node_id)
    edges = graph.get_edges_for_node(node_id)
    
    return {
        "node": node.to_cytoscape(),
        "neighbors": [n.to_cytoscape() for n in neighbors],
        "edges": [e.to_cytoscape() for e in edges],
        "connection_count": len(neighbors)
    }


@router.post("/ingest")
async def ingest_relationship(
    source_type: NodeType,
    source_id: str,
    source_label: str,
    target_type: NodeType,
    target_id: str,
    target_label: str,
    relationship: EdgeType,
    current_user: User = Depends(get_current_user)
):
    """
    Ingest a new relationship into the graph.
    
    Used by event processors to build the graph.
    """
    graph = get_fraud_graph()
    
    # Add/update nodes
    source_node = graph.add_node(GraphNode(
        id=source_id,
        type=source_type,
        label=source_label
    ))
    
    target_node = graph.add_node(GraphNode(
        id=target_id,
        type=target_type,
        label=target_label
    ))
    
    # Add edge
    edge = graph.add_edge(GraphEdge(
        source=source_id,
        target=target_id,
        type=relationship
    ))
    
    return {
        "status": "ingested",
        "source": source_node.id,
        "target": target_node.id,
        "relationship": relationship.value
    }


def _count_by_type(nodes: List[GraphNode]) -> Dict[str, int]:
    """Count nodes by type."""
    counts: Dict[str, int] = defaultdict(int)
    for node in nodes:
        counts[node.type.value] += 1
    return dict(counts)


__all__ = [
    'router',
    'FraudGraph',
    'GraphNode',
    'GraphEdge',
    'NodeType',
    'EdgeType',
    'get_fraud_graph'
]
