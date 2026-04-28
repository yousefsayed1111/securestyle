"""Module 5 - Decision Orchestrator.

Central decision-making module that receives threat predictions, intent
classifications, and anomaly scores, then decides the appropriate response:
block, isolate, redirect to honeynet, or continue monitoring.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from backend.app.models.database import store
from backend.app.schemas.common import (
    AttackerIntent,
    DecisionAction,
    IntentClassification,
    ThreatPrediction,
    ThreatSeverity,
)

logger = logging.getLogger(__name__)


class DecisionOrchestrator:
    """Fuses signals from multiple engines into a single response decision."""

    def __init__(self) -> None:
        self._decision_log: list[dict[str, Any]] = []

    def decide(
        self,
        predictions: list[ThreatPrediction],
        intents: list[IntentClassification],
        anomaly_scores: dict[str, float],
    ) -> list[dict[str, Any]]:
        """Produce a list of decisions based on all available signals."""
        decisions: list[dict[str, Any]] = []

        # Index intents by source IP for quick lookup
        intent_map: dict[str, IntentClassification] = {}
        for ic in intents:
            intent_map[ic.source_ip] = ic

        # Process each prediction
        for pred in predictions:
            src_ip = next(
                (i.split("=")[1] for i in pred.indicators if i.startswith("src=")),
                "unknown",
            )
            intent = intent_map.get(src_ip)
            anomaly = anomaly_scores.get(src_ip, 0.0)

            action = self._compute_action(pred, intent, anomaly)
            decision = {
                "timestamp": datetime.utcnow().isoformat(),
                "source_ip": src_ip,
                "action": action.value,
                "threat_probability": pred.threat_probability,
                "severity": pred.severity.value,
                "attack_type": pred.predicted_attack_type,
                "intent": intent.intent.value if intent else None,
                "intent_confidence": intent.confidence if intent else None,
                "anomaly_score": anomaly,
                "reasoning": self._build_reasoning(pred, intent, anomaly, action),
            }
            decisions.append(decision)
            self._decision_log.append(decision)

            store.add_alert({
                "type": "decision",
                "action": action.value,
                "source": src_ip,
                "severity": pred.severity.value,
                "reasoning": decision["reasoning"],
            })

        return decisions

    def _compute_action(
        self,
        pred: ThreatPrediction,
        intent: IntentClassification | None,
        anomaly: float,
    ) -> DecisionAction:
        """Multi-signal fusion to determine the best action."""
        # Critical threats with high-impact intents → redirect to honeynet
        high_impact_intents = {
            AttackerIntent.EXFILTRATION,
            AttackerIntent.LATERAL_MOVEMENT,
            AttackerIntent.COMMAND_AND_CONTROL,
            AttackerIntent.IMPACT,
        }
        if (
            pred.severity == ThreatSeverity.CRITICAL
            and intent
            and intent.intent in high_impact_intents
        ):
            return DecisionAction.REDIRECT

        if pred.severity == ThreatSeverity.CRITICAL:
            return DecisionAction.ISOLATE

        if pred.severity == ThreatSeverity.HIGH:
            if anomaly > 0.8:
                return DecisionAction.REDIRECT
            return DecisionAction.BLOCK

        if pred.severity == ThreatSeverity.MEDIUM:
            if intent and intent.confidence > 0.7:
                return DecisionAction.BLOCK
            return DecisionAction.ALERT

        return DecisionAction.MONITOR

    @staticmethod
    def _build_reasoning(
        pred: ThreatPrediction,
        intent: IntentClassification | None,
        anomaly: float,
        action: DecisionAction,
    ) -> str:
        parts = [
            f"Threat probability {pred.threat_probability:.1%} ({pred.severity.value})",
            f"anomaly={anomaly:.3f}",
        ]
        if intent:
            parts.append(f"intent={intent.intent.value}@{intent.confidence:.1%}")
        parts.append(f"→ {action.value}")
        return " | ".join(parts)

    @property
    def decision_history(self) -> list[dict[str, Any]]:
        return list(self._decision_log)


orchestrator = DecisionOrchestrator()
