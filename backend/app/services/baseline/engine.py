"""Module 2 - Behavior Baseline Engine.

Learns normal patterns for users, devices, and traffic flows. Maintains
a dynamic baseline using exponential moving averages that adapts to
legitimate changes while flagging genuine deviations.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from datetime import datetime
from typing import Any

from backend.app.models.database import store

logger = logging.getLogger(__name__)


class BehaviorBaselineEngine:
    """Maintains per-entity statistical baselines for anomaly scoring."""

    def __init__(self, alpha: float = 0.05) -> None:
        self._alpha = alpha  # EMA smoothing factor
        self._entity_stats: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "packet_rate_mean": 0.0,
                "packet_rate_var": 1.0,
                "payload_mean": 0.0,
                "payload_var": 1.0,
                "port_set": set(),
                "protocol_counts": defaultdict(int),
                "hour_histogram": [0] * 24,
                "total_events": 0,
                "last_updated": None,
            }
        )

    def update(self, events: list[dict[str, Any]]) -> dict[str, float]:
        """Update baselines with new events. Returns anomaly scores per entity."""
        anomaly_scores: dict[str, float] = {}
        for event in events:
            entity_id = event.get("src_ip", "unknown")
            stats = self._entity_stats[entity_id]
            payload = event.get("payload_size", 0)
            port = event.get("dst_port", 0)
            protocol = event.get("protocol", "TCP")
            ts = event.get("timestamp", datetime.utcnow().isoformat())

            hour = datetime.fromisoformat(ts).hour if isinstance(ts, str) else ts.hour

            # Exponential moving average for payload size
            old_mean = stats["payload_mean"]
            stats["payload_mean"] = (1 - self._alpha) * old_mean + self._alpha * payload
            stats["payload_var"] = (
                (1 - self._alpha) * stats["payload_var"]
                + self._alpha * (payload - old_mean) ** 2
            )

            stats["port_set"].add(port)
            stats["protocol_counts"][protocol] += 1
            stats["hour_histogram"][hour] += 1
            stats["total_events"] += 1
            stats["last_updated"] = ts

            # Anomaly score: how far this event is from baseline
            score = self._compute_anomaly_score(event, stats)
            anomaly_scores[entity_id] = max(
                anomaly_scores.get(entity_id, 0.0), score
            )

            # Persist baseline snapshot
            store.set_baseline(entity_id, {
                "payload_mean": stats["payload_mean"],
                "payload_var": stats["payload_var"],
                "unique_ports": len(stats["port_set"]),
                "total_events": stats["total_events"],
                "last_updated": ts,
            })

        return anomaly_scores

    def _compute_anomaly_score(self, event: dict, stats: dict) -> float:
        """Z-score based anomaly detection with multi-feature fusion."""
        score = 0.0
        payload = event.get("payload_size", 0)
        std = math.sqrt(max(stats["payload_var"], 1e-6))
        z_payload = abs(payload - stats["payload_mean"]) / std
        score += min(z_payload / 5.0, 1.0) * 0.4

        # Port novelty: new ports increase score
        port = event.get("dst_port", 0)
        if port not in stats["port_set"] and stats["total_events"] > 10:
            score += 0.3

        # Time anomaly: activity in unusual hours
        ts = event.get("timestamp", datetime.utcnow().isoformat())
        hour = datetime.fromisoformat(ts).hour if isinstance(ts, str) else ts.hour
        total_hour = sum(stats["hour_histogram"])
        if total_hour > 0:
            hour_freq = stats["hour_histogram"][hour] / total_hour
            if hour_freq < 0.02:
                score += 0.3

        return min(score, 1.0)

    def get_baseline(self, entity_id: str) -> dict[str, Any] | None:
        if entity_id in self._entity_stats:
            stats = self._entity_stats[entity_id]
            return {
                "payload_mean": stats["payload_mean"],
                "payload_var": stats["payload_var"],
                "unique_ports": len(stats["port_set"]),
                "total_events": stats["total_events"],
                "top_protocols": dict(stats["protocol_counts"]),
                "last_updated": stats["last_updated"],
            }
        return None

    def get_all_entity_ids(self) -> list[str]:
        return list(self._entity_stats.keys())


baseline_engine = BehaviorBaselineEngine()
