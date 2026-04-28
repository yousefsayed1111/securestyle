"""Module 18 - Time Prediction Engine.

Predicts WHEN attacks will occur using temporal pattern analysis,
cyclical trend detection, and threat actor behaviour modelling.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from backend.app.schemas.common import AttackTimelinePrediction

logger = logging.getLogger(__name__)


class TimePredictionEngine:
    """Predicts the timing of future attacks."""

    def __init__(self) -> None:
        self._attack_history: list[dict[str, Any]] = []
        self._hourly_distribution: list[int] = [0] * 24
        self._daily_distribution: list[int] = [0] * 7
        self._predictions: list[AttackTimelinePrediction] = []

    def record_attack(self, attack_data: dict[str, Any]) -> None:
        """Record an attack for temporal analysis."""
        ts = attack_data.get("timestamp", datetime.utcnow().isoformat())
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        self._attack_history.append({**attack_data, "parsed_timestamp": ts})
        self._hourly_distribution[ts.hour] += 1
        self._daily_distribution[ts.weekday()] += 1

    def predict(self) -> list[dict[str, Any]]:
        """Generate attack timing predictions."""
        predictions: list[dict[str, Any]] = []

        if len(self._attack_history) < 3:
            # Not enough data; produce a baseline prediction
            now = datetime.utcnow()
            pred = AttackTimelinePrediction(
                predicted_window_start=now + timedelta(hours=1),
                predicted_window_end=now + timedelta(hours=6),
                confidence=0.3,
                attack_type="unknown",
                target_assets=["general"],
            )
            self._predictions.append(pred)
            return [pred.model_dump()]

        # Temporal pattern analysis
        peak_hour = self._hourly_distribution.index(max(self._hourly_distribution))
        peak_day = self._daily_distribution.index(max(self._daily_distribution))

        # Calculate inter-attack intervals
        timestamps = sorted(
            a["parsed_timestamp"] for a in self._attack_history
        )
        intervals = [
            (timestamps[i] - timestamps[i - 1]).total_seconds()
            for i in range(1, len(timestamps))
        ]

        if intervals:
            mean_interval = sum(intervals) / len(intervals)
            variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
            std_interval = math.sqrt(variance)

            # Predict next attack window
            last_attack = timestamps[-1]
            predicted_start = last_attack + timedelta(seconds=max(mean_interval - std_interval, 60))
            predicted_end = last_attack + timedelta(seconds=mean_interval + std_interval)

            # Confidence based on regularity
            cv = std_interval / max(mean_interval, 1)
            confidence = max(0.1, min(1.0 / (1.0 + cv), 0.95))

            # Attack type prediction from most common recent types
            type_counts: dict[str, int] = defaultdict(int)
            for a in self._attack_history[-20:]:
                type_counts[a.get("attack_type", "unknown")] += 1
            predicted_type = max(type_counts, key=type_counts.get)  # type: ignore[arg-type]

            pred = AttackTimelinePrediction(
                predicted_window_start=predicted_start,
                predicted_window_end=predicted_end,
                confidence=round(confidence, 4),
                attack_type=predicted_type,
                target_assets=self._predict_targets(),
            )
            self._predictions.append(pred)
            predictions.append(pred.model_dump())

        # Cyclical prediction
        now = datetime.utcnow()
        days_ahead = (peak_day - now.weekday()) % 7
        if days_ahead == 0:
            days_ahead = 7
        next_peak = now.replace(hour=peak_hour, minute=0, second=0) + timedelta(days=days_ahead)

        cyclical_pred = AttackTimelinePrediction(
            predicted_window_start=next_peak - timedelta(hours=2),
            predicted_window_end=next_peak + timedelta(hours=2),
            confidence=round(self._cyclical_confidence(), 4),
            attack_type="cyclical_pattern",
            target_assets=self._predict_targets(),
        )
        self._predictions.append(cyclical_pred)
        predictions.append(cyclical_pred.model_dump())

        return predictions

    def _predict_targets(self) -> list[str]:
        """Predict likely target assets based on history."""
        target_counts: dict[str, int] = defaultdict(int)
        for a in self._attack_history:
            for target in a.get("target_assets", ["general"]):
                target_counts[target] += 1
        if not target_counts:
            return ["general"]
        sorted_targets = sorted(target_counts, key=target_counts.get, reverse=True)  # type: ignore[arg-type]
        return sorted_targets[:3]

    def _cyclical_confidence(self) -> float:
        """Confidence in cyclical pattern based on distribution entropy."""
        total = sum(self._hourly_distribution)
        if total == 0:
            return 0.1
        probs = [h / total for h in self._hourly_distribution if h > 0]
        entropy = -sum(p * math.log2(p) for p in probs)
        max_entropy = math.log2(24)
        return max(0.1, 1.0 - entropy / max_entropy)

    def get_temporal_profile(self) -> dict[str, Any]:
        return {
            "total_attacks_recorded": len(self._attack_history),
            "hourly_distribution": list(self._hourly_distribution),
            "daily_distribution": list(self._daily_distribution),
            "predictions_made": len(self._predictions),
        }

    def get_predictions(self) -> list[dict[str, Any]]:
        return [p.model_dump() for p in self._predictions]


time_prediction_engine = TimePredictionEngine()
