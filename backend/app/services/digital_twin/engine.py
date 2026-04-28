"""Module 14 - Digital Twin System.

Creates a virtual replica of the production network, allowing safe
simulation of attacks and testing of defense improvements without
risking the real infrastructure.
"""

from __future__ import annotations

import logging
import random
import uuid
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


class NetworkNode:
    """A node in the digital twin network."""

    def __init__(
        self,
        name: str,
        node_type: str,
        ip: str,
        services: list[dict[str, Any]] | None = None,
    ) -> None:
        self.node_id = uuid.uuid4().hex[:12]
        self.name = name
        self.node_type = node_type  # server, workstation, router, firewall, switch
        self.ip = ip
        self.services = services or []
        self.connections: list[str] = []  # node_ids
        self.vulnerabilities: list[dict[str, Any]] = []
        self.status = "active"

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "name": self.name,
            "type": self.node_type,
            "ip": self.ip,
            "services": self.services,
            "connections": self.connections,
            "vulnerability_count": len(self.vulnerabilities),
            "status": self.status,
        }


class DigitalTwinEngine:
    """Manages a virtual replica of the network for safe testing."""

    def __init__(self) -> None:
        self._nodes: dict[str, NetworkNode] = {}
        self._simulation_history: list[dict[str, Any]] = []
        self._twin_created_at: datetime | None = None

    def create_twin(self, topology: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create a digital twin from a topology spec or generate a default one."""
        if topology:
            return self._build_from_topology(topology)
        return self._generate_default_twin()

    def _generate_default_twin(self) -> dict[str, Any]:
        """Generate a realistic enterprise network topology."""
        self._nodes.clear()

        # Core infrastructure
        nodes_spec = [
            ("fw-01", "firewall", "10.0.0.1", [{"name": "iptables", "port": None}]),
            ("router-01", "router", "10.0.0.2", []),
            ("switch-01", "switch", "10.0.1.1", []),
            ("switch-02", "switch", "10.0.2.1", []),
            # DMZ
            ("web-01", "server", "10.0.1.10", [
                {"name": "nginx", "port": 80},
                {"name": "nginx-ssl", "port": 443},
            ]),
            ("web-02", "server", "10.0.1.11", [
                {"name": "apache", "port": 80},
                {"name": "apache-ssl", "port": 443},
            ]),
            ("api-01", "server", "10.0.1.20", [
                {"name": "fastapi", "port": 8080},
            ]),
            # Internal
            ("db-primary", "server", "10.0.2.10", [
                {"name": "postgresql", "port": 5432},
            ]),
            ("db-replica", "server", "10.0.2.11", [
                {"name": "postgresql", "port": 5432},
            ]),
            ("cache-01", "server", "10.0.2.20", [
                {"name": "redis", "port": 6379},
            ]),
            ("ldap-01", "server", "10.0.2.30", [
                {"name": "openldap", "port": 389},
            ]),
            ("mail-01", "server", "10.0.2.40", [
                {"name": "postfix", "port": 25},
                {"name": "dovecot", "port": 993},
            ]),
            # Workstations
            ("ws-eng-01", "workstation", "10.0.3.10", [{"name": "ssh", "port": 22}]),
            ("ws-eng-02", "workstation", "10.0.3.11", [{"name": "ssh", "port": 22}]),
            ("ws-ops-01", "workstation", "10.0.3.20", [{"name": "ssh", "port": 22}]),
        ]

        for name, ntype, ip, services in nodes_spec:
            node = NetworkNode(name, ntype, ip, services)
            self._nodes[node.node_id] = node

        # Build connections
        nodes = list(self._nodes.values())
        fw = nodes[0]
        router = nodes[1]
        fw.connections.append(router.node_id)
        router.connections.append(fw.node_id)

        for node in nodes[2:]:
            router.connections.append(node.node_id)
            node.connections.append(router.node_id)

        self._twin_created_at = datetime.utcnow()

        return {
            "created_at": self._twin_created_at.isoformat(),
            "node_count": len(self._nodes),
            "nodes": [n.to_dict() for n in self._nodes.values()],
        }

    def _build_from_topology(self, topology: dict[str, Any]) -> dict[str, Any]:
        """Build twin from explicit topology specification."""
        self._nodes.clear()
        for node_spec in topology.get("nodes", []):
            node = NetworkNode(
                name=node_spec["name"],
                node_type=node_spec.get("type", "server"),
                ip=node_spec.get("ip", "0.0.0.0"),
                services=node_spec.get("services", []),
            )
            self._nodes[node.node_id] = node

        self._twin_created_at = datetime.utcnow()
        return {
            "created_at": self._twin_created_at.isoformat(),
            "node_count": len(self._nodes),
            "nodes": [n.to_dict() for n in self._nodes.values()],
        }

    def simulate_attack(
        self, attack_type: str, target_node_id: str | None = None,
    ) -> dict[str, Any]:
        """Simulate an attack on the digital twin and measure impact."""
        if not self._nodes:
            return {"error": "No digital twin created yet"}

        target = (
            self._nodes.get(target_node_id)
            if target_node_id
            else random.choice(list(self._nodes.values()))
        )
        if not target:
            return {"error": "Target node not found"}

        sim_id = uuid.uuid4().hex[:12]
        compromised: list[str] = []
        attack_path: list[dict[str, Any]] = []

        # Simulate attack progression
        current = target
        for step in range(random.randint(1, 5)):
            success = random.random() > 0.4
            attack_path.append({
                "step": step + 1,
                "node": current.name,
                "ip": current.ip,
                "success": success,
                "action": attack_type,
            })
            if success:
                compromised.append(current.node_id)
                if current.connections:
                    next_id = random.choice(current.connections)
                    next_node = self._nodes.get(next_id)
                    if next_node:
                        current = next_node
                    else:
                        break
                else:
                    break
            else:
                break

        result = {
            "sim_id": sim_id,
            "attack_type": attack_type,
            "target": target.to_dict(),
            "compromised_nodes": len(compromised),
            "total_nodes": len(self._nodes),
            "impact_percentage": len(compromised) / len(self._nodes) * 100,
            "attack_path": attack_path,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._simulation_history.append(result)
        return result

    def test_defense(self, defense_rules: list[dict[str, Any]]) -> dict[str, Any]:
        """Test a set of defense rules against the twin."""
        attack_types = ["port_scan", "brute_force", "lateral_movement",
                        "data_exfiltration", "c2_beacon"]
        results = []
        for attack_type in attack_types:
            sim = self.simulate_attack(attack_type)
            blocked = any(
                rule.get("type") == attack_type or
                rule.get("action") == "block"
                for rule in defense_rules
            )
            sim["defense_effective"] = blocked or sim["compromised_nodes"] == 0
            results.append(sim)

        effective = sum(1 for r in results if r["defense_effective"])
        return {
            "tests_run": len(results),
            "effective": effective,
            "effectiveness_rate": effective / len(results) * 100,
            "results": results,
        }

    def get_topology(self) -> dict[str, Any]:
        return {
            "created_at": self._twin_created_at.isoformat() if self._twin_created_at else None,
            "node_count": len(self._nodes),
            "nodes": [n.to_dict() for n in self._nodes.values()],
        }

    def get_simulation_history(self) -> list[dict[str, Any]]:
        return list(self._simulation_history)


digital_twin_engine = DigitalTwinEngine()
