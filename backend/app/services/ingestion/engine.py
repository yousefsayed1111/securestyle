"""Module 1 - Network Ingestion Layer.

Captures real-time network traffic (PCAP, NetFlow, syslog), normalises it
into a canonical event schema, and streams it to downstream consumers via
an internal event bus (backed by Kafka in production).
"""

from __future__ import annotations

import hashlib
import logging
import random
import time
from datetime import datetime
from typing import Any

from backend.app.models.database import store
from backend.app.schemas.common import NetworkEvent

logger = logging.getLogger(__name__)

PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "SSH", "TLS"]
COMMON_PORTS = [22, 53, 80, 443, 3306, 5432, 8080, 8443, 6379, 27017]


class NetworkIngestionEngine:
    """Ingest, normalise, and enrich raw network events."""

    def __init__(self) -> None:
        self._running = False
        self._processed_count = 0

    def normalise_event(self, raw: dict[str, Any]) -> NetworkEvent:
        """Convert heterogeneous input into canonical NetworkEvent."""
        return NetworkEvent(
            timestamp=datetime.fromisoformat(raw["timestamp"])
            if "timestamp" in raw
            else datetime.utcnow(),
            src_ip=raw.get("src_ip", raw.get("source", "0.0.0.0")),
            dst_ip=raw.get("dst_ip", raw.get("destination", "0.0.0.0")),
            src_port=int(raw.get("src_port", raw.get("sport", 0))),
            dst_port=int(raw.get("dst_port", raw.get("dport", 0))),
            protocol=raw.get("protocol", "TCP").upper(),
            payload_size=int(raw.get("payload_size", raw.get("bytes", 0))),
            flags=raw.get("flags", []),
            metadata=raw.get("metadata", {}),
        )

    def enrich_event(self, event: NetworkEvent) -> dict[str, Any]:
        """Add derived fields useful for downstream analytics."""
        data = event.model_dump()
        data["event_hash"] = hashlib.sha256(
            f"{event.src_ip}:{event.src_port}->{event.dst_ip}:{event.dst_port}"
            f"@{event.timestamp.isoformat()}".encode()
        ).hexdigest()[:16]
        data["direction"] = (
            "inbound" if event.dst_port in COMMON_PORTS else "outbound"
        )
        data["timestamp"] = event.timestamp.isoformat()
        return data

    def ingest(self, raw_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalise, enrich, and persist a batch of raw events."""
        results: list[dict[str, Any]] = []
        for raw in raw_events:
            event = self.normalise_event(raw)
            enriched = self.enrich_event(event)
            store.add_event(enriched)
            results.append(enriched)
            self._processed_count += 1
        logger.info("Ingested %d events (total: %d)", len(results), self._processed_count)
        return results

    def generate_synthetic_traffic(self, count: int = 100) -> list[dict[str, Any]]:
        """Generate realistic synthetic traffic for testing / demo."""
        events: list[dict[str, Any]] = []
        base_ts = time.time()
        for i in range(count):
            ts = datetime.utcfromtimestamp(base_ts + i * 0.01)
            events.append(
                {
                    "timestamp": ts.isoformat(),
                    "src_ip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                    "dst_ip": f"10.0.{random.randint(0, 10)}.{random.randint(1, 254)}",
                    "src_port": random.randint(1024, 65535),
                    "dst_port": random.choice(COMMON_PORTS),
                    "protocol": random.choice(PROTOCOLS),
                    "payload_size": random.randint(40, 15000),
                    "flags": random.sample(["SYN", "ACK", "FIN", "RST", "PSH"], k=random.randint(0, 3)),
                }
            )
        return self.ingest(events)

    @property
    def processed_count(self) -> int:
        return self._processed_count


ingestion_engine = NetworkIngestionEngine()
