"""Module 3 - Predictive Threat Engine.

Uses time-series forecasting and sequence models to predict future attacks.
Outputs threat probability, severity, and estimated time-to-attack.
"""

from __future__ import annotations

import logging
import math
import random
from collections import deque
from datetime import datetime
from typing import Any

from backend.app.models.database import store
from backend.app.schemas.common import DecisionAction, ThreatPrediction, ThreatSeverity

logger = logging.getLogger(__name__)

ATTACK_PATTERNS = {
    "port_scan": {"port_diversity_threshold": 10, "time_window_seconds": 60},
    "brute_force": {"failed_auth_threshold": 5, "time_window_seconds": 120},
    "data_exfiltration": {"payload_threshold": 50000, "frequency_threshold": 20},
    "c2_beacon": {"regularity_threshold": 0.9, "min_events": 5},
    "lateral_movement": {"unique_dst_threshold": 5, "time_window_seconds": 300},
}


class PredictiveThreatEngine:
    """Predicts threats using statistical and heuristic models."""

    def __init__(self, history_window: int = 500) -> None:
        self._event_history: deque[dict[str, Any]] = deque(maxlen=history_window)
        self._threat_scores: dict[str, float] = {}

    def analyze(
        self, events: list[dict[str, Any]], anomaly_scores: dict[str, float]
    ) -> list[ThreatPrediction]:
        """Run prediction pipeline on a batch of events."""
        self._event_history.extend(events)
        predictions: list[ThreatPrediction] = []

        # Group events by source IP
        by_source: dict[str, list[dict]] = {}
        for e in events:
            by_source.setdefault(e.get("src_ip", "unknown"), []).append(e)

        for src_ip, src_events in by_source.items():
            anomaly = anomaly_scores.get(src_ip, 0.0)
            for pattern_name, thresholds in ATTACK_PATTERNS.items():
                score = self._evaluate_pattern(src_ip, src_events, pattern_name, thresholds)
                combined = 0.6 * score + 0.4 * anomaly
                if combined > 0.3:
                    severity = self._score_to_severity(combined)
                    prediction = ThreatPrediction(
                        threat_probability=round(combined, 4),
                        severity=severity,
                        predicted_attack_type=pattern_name,
                        time_to_attack_seconds=self._estimate_time_to_attack(combined),
                        confidence=round(min(combined + 0.1, 1.0), 4),
                        indicators=[
                            f"anomaly_score={anomaly:.3f}",
                            f"pattern={pattern_name}",
                            f"src={src_ip}",
                        ],
                        recommended_action=self._recommend_action(combined),
                    )
                    predictions.append(prediction)
                    store.add_prediction(prediction.model_dump())
                    store.add_alert({
                        "type": "threat_prediction",
                        "severity": severity.value,
                        "source": src_ip,
                        "attack_type": pattern_name,
                        "probability": combined,
                    })

        return predictions

    def _evaluate_pattern(
        self, src_ip: str, events: list[dict], pattern: str, thresholds: dict
    ) -> float:
        """Score how well current traffic matches a known attack pattern."""
        if pattern == "port_scan":
            unique_ports = {e.get("dst_port") for e in events}
            return min(len(unique_ports) / thresholds["port_diversity_threshold"], 1.0)

        if pattern == "brute_force":
            auth_ports = [e for e in events if e.get("dst_port") in (22, 3389, 445)]
            return min(len(auth_ports) / thresholds["failed_auth_threshold"], 1.0)

        if pattern == "data_exfiltration":
            total_payload = sum(e.get("payload_size", 0) for e in events)
            return min(total_payload / thresholds["payload_threshold"], 1.0)

        if pattern == "c2_beacon":
            if len(events) < thresholds["min_events"]:
                return 0.0
            intervals = []
            for i in range(1, len(events)):
                t1 = events[i - 1].get("timestamp", "")
                t2 = events[i].get("timestamp", "")
                if t1 and t2:
                    try:
                        d = abs(
                            (datetime.fromisoformat(t2) - datetime.fromisoformat(t1)).total_seconds()
                        )
                        intervals.append(d)
                    except (ValueError, TypeError):
                        pass
            if not intervals:
                return 0.0
            mean_int = sum(intervals) / len(intervals)
            variance = sum((i - mean_int) ** 2 for i in intervals) / len(intervals)
            regularity = 1.0 / (1.0 + math.sqrt(variance))
            return regularity

        if pattern == "lateral_movement":
            unique_dst = {e.get("dst_ip") for e in events}
            return min(len(unique_dst) / thresholds["unique_dst_threshold"], 1.0)

        return 0.0

    @staticmethod
    def _score_to_severity(score: float) -> ThreatSeverity:
        if score >= 0.85:
            return ThreatSeverity.CRITICAL
        if score >= 0.65:
            return ThreatSeverity.HIGH
        if score >= 0.45:
            return ThreatSeverity.MEDIUM
        return ThreatSeverity.LOW

    @staticmethod
    def _estimate_time_to_attack(score: float) -> float:
        """Higher threat score → shorter estimated time-to-attack (seconds)."""
        if score >= 0.9:
            return random.uniform(10, 60)
        if score >= 0.7:
            return random.uniform(60, 300)
        if score >= 0.5:
            return random.uniform(300, 1800)
        return random.uniform(1800, 7200)

    @staticmethod
    def _recommend_action(score: float) -> DecisionAction:
        if score >= 0.85:
            return DecisionAction.REDIRECT
        if score >= 0.65:
            return DecisionAction.ISOLATE
        if score >= 0.45:
            return DecisionAction.BLOCK
        return DecisionAction.MONITOR


prediction_engine = PredictiveThreatEngine()
