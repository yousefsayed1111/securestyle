"""Module 15 - Adaptive Network (Moving Target Defense).

Dynamically changes IP addresses, ports, and network topology to
make the attack surface unpredictable. Legitimate services are
transparently rerouted while attackers lose track of targets.
"""

from __future__ import annotations

import logging
import random
import uuid
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


class MTDTransformation:
    """A single MTD transformation record."""

    def __init__(
        self,
        transform_type: str,
        original: dict[str, Any],
        new: dict[str, Any],
    ) -> None:
        self.transform_id = uuid.uuid4().hex[:12]
        self.transform_type = transform_type  # ip_rotation | port_shuffle | topology_change
        self.original = original
        self.new = new
        self.applied_at = datetime.utcnow()
        self.active = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "transform_id": self.transform_id,
            "type": self.transform_type,
            "original": self.original,
            "new": self.new,
            "applied_at": self.applied_at.isoformat(),
            "active": self.active,
        }


class MovingTargetDefenseEngine:
    """Manages dynamic network transformations."""

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled
        self._transformations: list[MTDTransformation] = []
        self._ip_mappings: dict[str, str] = {}  # original -> current
        self._port_mappings: dict[int, int] = {}

    def rotate_ips(self, targets: list[str] | None = None) -> list[dict[str, Any]]:
        """Rotate IP addresses for specified or all tracked hosts."""
        if not self._enabled:
            return []

        if targets is None:
            targets = list(self._ip_mappings.keys()) or [
                f"10.0.{random.randint(0, 10)}.{random.randint(1, 254)}"
                for _ in range(5)
            ]

        results: list[dict[str, Any]] = []
        for original_ip in targets:
            new_ip = f"10.0.{random.randint(0, 254)}.{random.randint(1, 254)}"
            transform = MTDTransformation(
                "ip_rotation",
                {"ip": original_ip},
                {"ip": new_ip},
            )
            self._transformations.append(transform)
            self._ip_mappings[original_ip] = new_ip
            results.append(transform.to_dict())

        logger.info("Rotated %d IP addresses", len(results))
        return results

    def shuffle_ports(
        self, services: dict[str, int] | None = None,
    ) -> list[dict[str, Any]]:
        """Shuffle service ports to non-standard assignments."""
        if not self._enabled:
            return []

        if services is None:
            services = {"ssh": 22, "http": 80, "https": 443, "api": 8080}

        results: list[dict[str, Any]] = []
        used_ports: set[int] = set()
        for service_name, original_port in services.items():
            new_port = random.randint(10000, 60000)
            while new_port in used_ports:
                new_port = random.randint(10000, 60000)
            used_ports.add(new_port)

            transform = MTDTransformation(
                "port_shuffle",
                {"service": service_name, "port": original_port},
                {"service": service_name, "port": new_port},
            )
            self._transformations.append(transform)
            self._port_mappings[original_port] = new_port
            results.append(transform.to_dict())

        logger.info("Shuffled %d service ports", len(results))
        return results

    def change_topology(self) -> dict[str, Any]:
        """Randomise network segment assignments."""
        if not self._enabled:
            return {"status": "disabled"}

        segments = ["dmz", "internal", "restricted", "management"]
        changes: list[dict[str, Any]] = []

        for ip in list(self._ip_mappings.values()) or ["10.0.1.10", "10.0.2.10"]:
            old_segment = random.choice(segments)
            new_segment = random.choice([s for s in segments if s != old_segment])
            transform = MTDTransformation(
                "topology_change",
                {"ip": ip, "segment": old_segment},
                {"ip": ip, "segment": new_segment},
            )
            self._transformations.append(transform)
            changes.append(transform.to_dict())

        return {
            "changes": changes,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def get_current_mappings(self) -> dict[str, Any]:
        return {
            "ip_mappings": dict(self._ip_mappings),
            "port_mappings": {str(k): v for k, v in self._port_mappings.items()},
            "total_transformations": len(self._transformations),
            "active_transformations": sum(
                1 for t in self._transformations if t.active
            ),
        }

    def get_transformation_history(self) -> list[dict[str, Any]]:
        return [t.to_dict() for t in self._transformations]


mtd_engine = MovingTargetDefenseEngine()
