"""Module 19 - Global Threat Intelligence Network.

Shares threat indicators across Sentinel-X instances in a collective
defense model. Supports STIX/TAXII-compatible indicator exchange.
"""

from __future__ import annotations

import logging
import random
import uuid
from datetime import datetime
from typing import Any

from backend.app.models.database import store
from backend.app.schemas.common import ThreatIntelIndicator, ThreatSeverity

logger = logging.getLogger(__name__)


class ThreatIntelligenceEngine:
    """Global threat intelligence sharing and consumption."""

    def __init__(self) -> None:
        self._indicators: dict[str, ThreatIntelIndicator] = {}
        self._peers: list[dict[str, Any]] = []
        self._shared_count = 0
        self._received_count = 0

    def add_indicator(self, indicator: ThreatIntelIndicator) -> dict[str, Any]:
        """Add a threat intelligence indicator."""
        key = f"{indicator.indicator_type}:{indicator.value}"
        self._indicators[key] = indicator
        store.add_threat_intel(indicator.model_dump())
        return {"key": key, "status": "added"}

    def add_indicator_from_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        indicator = ThreatIntelIndicator(
            indicator_type=data.get("type", "ip"),
            value=data.get("value", ""),
            severity=ThreatSeverity(data.get("severity", "medium")),
            source=data.get("source", "local"),
            first_seen=datetime.fromisoformat(data["first_seen"])
            if "first_seen" in data
            else datetime.utcnow(),
            last_seen=datetime.fromisoformat(data["last_seen"])
            if "last_seen" in data
            else datetime.utcnow(),
            tags=data.get("tags", []),
        )
        return self.add_indicator(indicator)

    def check_indicator(self, indicator_type: str, value: str) -> dict[str, Any] | None:
        """Check if a value matches known threat intelligence."""
        key = f"{indicator_type}:{value}"
        indicator = self._indicators.get(key)
        if indicator:
            return {
                "match": True,
                "indicator": indicator.model_dump(),
            }
        return {"match": False, "indicator_type": indicator_type, "value": value}

    def bulk_check(self, items: list[dict[str, str]]) -> list[dict[str, Any]]:
        """Check multiple indicators at once."""
        return [
            self.check_indicator(item["type"], item["value"])
            for item in items
        ]

    def share_with_peers(self) -> dict[str, Any]:
        """Share local indicators with peer instances."""
        # In production, this would use STIX/TAXII or a custom protocol
        indicators_to_share = [
            ind.model_dump()
            for ind in self._indicators.values()
            if (datetime.utcnow() - ind.last_seen).total_seconds() < ind.ttl_seconds
        ]
        self._shared_count += len(indicators_to_share)
        return {
            "shared_count": len(indicators_to_share),
            "peer_count": len(self._peers),
            "total_shared": self._shared_count,
        }

    def receive_from_peer(self, peer_data: dict[str, Any]) -> dict[str, Any]:
        """Receive indicators from a peer instance."""
        received = 0
        for ind_data in peer_data.get("indicators", []):
            self.add_indicator_from_dict(ind_data)
            received += 1
        self._received_count += received
        return {"received": received, "total_received": self._received_count}

    def register_peer(self, peer_info: dict[str, Any]) -> dict[str, Any]:
        """Register a peer for threat intelligence sharing."""
        peer = {
            "peer_id": uuid.uuid4().hex[:12],
            "url": peer_info.get("url", ""),
            "name": peer_info.get("name", "unknown"),
            "registered_at": datetime.utcnow().isoformat(),
            "status": "active",
        }
        self._peers.append(peer)
        return peer

    def get_indicators(self, severity: str | None = None) -> list[dict[str, Any]]:
        indicators = list(self._indicators.values())
        if severity:
            indicators = [i for i in indicators if i.severity.value == severity]
        return [i.model_dump() for i in indicators]

    def get_stats(self) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for ind in self._indicators.values():
            by_type[ind.indicator_type] = by_type.get(ind.indicator_type, 0) + 1
            by_severity[ind.severity.value] = by_severity.get(ind.severity.value, 0) + 1

        return {
            "total_indicators": len(self._indicators),
            "by_type": by_type,
            "by_severity": by_severity,
            "peers": len(self._peers),
            "shared_total": self._shared_count,
            "received_total": self._received_count,
        }

    def generate_sample_indicators(self, count: int = 50) -> list[dict[str, Any]]:
        """Generate sample threat intelligence for demo."""
        results = []
        for i in range(count):
            ind_type = ["ip", "domain", "hash", "url"][i % 4]
            if ind_type == "ip":
                value = f"{random.choice([45, 91, 185, 203])}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            elif ind_type == "domain":
                value = f"malware-{uuid.uuid4().hex[:6]}.evil.example"
            elif ind_type == "hash":
                value = uuid.uuid4().hex + uuid.uuid4().hex[:32]
            else:
                value = f"https://phishing-{uuid.uuid4().hex[:6]}.example/login"

            severity = ["low", "medium", "high", "critical"][i % 4]
            result = self.add_indicator_from_dict({
                "type": ind_type,
                "value": value,
                "severity": severity,
                "source": "sentinel-x-demo",
                "tags": ["demo", ind_type],
            })
            results.append(result)
        return results


threat_intel_engine = ThreatIntelligenceEngine()
