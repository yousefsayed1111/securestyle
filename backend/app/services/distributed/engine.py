"""Module 16 - Distributed Defense System.

Each endpoint acts as both a sensor and a defender in a peer-to-peer
defense model. Endpoints share threat intelligence and coordinate
responses without a single point of failure.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


class DefenseNode:
    """An endpoint that participates in the distributed defense mesh."""

    def __init__(self, hostname: str, ip: str, node_type: str = "sensor") -> None:
        self.node_id = uuid.uuid4().hex[:12]
        self.hostname = hostname
        self.ip = ip
        self.node_type = node_type  # sensor | defender | hybrid
        self.peers: list[str] = []
        self.local_threats: list[dict[str, Any]] = []
        self.status = "active"
        self.last_heartbeat = datetime.utcnow()
        self.capabilities: list[str] = ["detect", "report"]
        if node_type in ("defender", "hybrid"):
            self.capabilities.extend(["block", "isolate", "redirect"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "hostname": self.hostname,
            "ip": self.ip,
            "type": self.node_type,
            "peers": self.peers,
            "threat_count": len(self.local_threats),
            "status": self.status,
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "capabilities": self.capabilities,
        }


class DistributedDefenseEngine:
    """Manages a mesh of defense nodes."""

    def __init__(self) -> None:
        self._nodes: dict[str, DefenseNode] = {}

    def register_node(
        self, hostname: str, ip: str, node_type: str = "hybrid",
    ) -> dict[str, Any]:
        """Register a new endpoint in the defense mesh."""
        node = DefenseNode(hostname, ip, node_type)

        # Auto-peer with existing nodes
        for existing in self._nodes.values():
            node.peers.append(existing.node_id)
            existing.peers.append(node.node_id)

        self._nodes[node.node_id] = node
        logger.info("Registered defense node: %s (%s)", hostname, ip)
        return node.to_dict()

    def report_threat(self, node_id: str, threat: dict[str, Any]) -> dict[str, Any]:
        """A node reports a local threat; propagate to peers."""
        node = self._nodes.get(node_id)
        if not node:
            return {"error": "Node not found"}

        threat["reported_by"] = node_id
        threat["timestamp"] = datetime.utcnow().isoformat()
        node.local_threats.append(threat)

        # Propagate to peers
        propagated_to: list[str] = []
        for peer_id in node.peers:
            peer = self._nodes.get(peer_id)
            if peer and peer.status == "active":
                peer.local_threats.append(threat)
                propagated_to.append(peer_id)

        return {
            "threat": threat,
            "propagated_to": len(propagated_to),
            "total_nodes_aware": len(propagated_to) + 1,
        }

    def coordinate_response(
        self, threat: dict[str, Any],
    ) -> dict[str, Any]:
        """Coordinate a distributed response to a threat."""
        responding_nodes: list[dict[str, Any]] = []
        for node in self._nodes.values():
            if node.status != "active":
                continue
            if "block" in node.capabilities:
                responding_nodes.append({
                    "node_id": node.node_id,
                    "action": "block",
                    "target": threat.get("source_ip", "unknown"),
                })

        return {
            "threat": threat,
            "responding_nodes": len(responding_nodes),
            "responses": responding_nodes,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def heartbeat(self, node_id: str) -> bool:
        node = self._nodes.get(node_id)
        if node:
            node.last_heartbeat = datetime.utcnow()
            node.status = "active"
            return True
        return False

    def get_mesh_status(self) -> dict[str, Any]:
        active = sum(1 for n in self._nodes.values() if n.status == "active")
        return {
            "total_nodes": len(self._nodes),
            "active_nodes": active,
            "total_threats": sum(len(n.local_threats) for n in self._nodes.values()),
            "nodes": [n.to_dict() for n in self._nodes.values()],
        }

    def generate_default_mesh(self, count: int = 10) -> dict[str, Any]:
        """Generate a default mesh of defense nodes for demo purposes."""
        for i in range(count):
            ntype = "hybrid" if i < 3 else ("defender" if i < 6 else "sensor")
            self.register_node(
                hostname=f"node-{i:03d}",
                ip=f"10.0.{i // 254}.{(i % 254) + 1}",
                node_type=ntype,
            )
        return self.get_mesh_status()


distributed_engine = DistributedDefenseEngine()
