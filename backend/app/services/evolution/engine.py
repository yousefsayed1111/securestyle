"""Module 11 - Self-Evolving Engine.

Continuously learns from attacks by retraining detection models,
updating anomaly thresholds, and generating new detection rules
based on observed attack patterns.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


class EvolutionRecord:
    """Tracks a single evolution step."""

    def __init__(self, trigger: str, changes: list[dict[str, Any]]) -> None:
        self.timestamp = datetime.utcnow()
        self.trigger = trigger
        self.changes = changes

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "trigger": self.trigger,
            "changes": self.changes,
        }


class SelfEvolvingEngine:
    """Adapts detection and defense parameters over time."""

    def __init__(self) -> None:
        self._evolution_history: list[EvolutionRecord] = []
        self._detection_thresholds: dict[str, float] = {
            "anomaly_threshold": 0.5,
            "port_scan_threshold": 10,
            "brute_force_threshold": 5,
            "exfiltration_payload_threshold": 50000,
            "c2_regularity_threshold": 0.9,
        }
        self._generated_rules: list[dict[str, Any]] = []

    def evolve(self, attack_data: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze recent attacks and evolve detection parameters."""
        changes: list[dict[str, Any]] = []

        # Analyze attack patterns to adjust thresholds
        for attack in attack_data:
            attack_type = attack.get("attack_type", "")
            probability = attack.get("threat_probability", 0.0)

            # If we're seeing attacks at lower probability thresholds,
            # tighten the detection
            if probability < 0.5 and attack_type:
                threshold_key = self._attack_type_to_threshold(attack_type)
                if threshold_key and threshold_key in self._detection_thresholds:
                    old_val = self._detection_thresholds[threshold_key]
                    new_val = old_val * 0.9  # Tighten by 10%
                    self._detection_thresholds[threshold_key] = new_val
                    changes.append({
                        "type": "threshold_adjustment",
                        "parameter": threshold_key,
                        "old_value": old_val,
                        "new_value": new_val,
                        "reason": f"Attack detected at low probability ({probability:.2f})",
                    })

            # Generate new detection rule if novel pattern seen
            new_rule = self._generate_rule(attack)
            if new_rule:
                self._generated_rules.append(new_rule)
                changes.append({"type": "new_rule", "rule": new_rule})

        if changes:
            record = EvolutionRecord(trigger="attack_analysis", changes=changes)
            self._evolution_history.append(record)

        return {
            "evolution_step": len(self._evolution_history),
            "changes_made": len(changes),
            "current_thresholds": dict(self._detection_thresholds),
            "total_rules": len(self._generated_rules),
        }

    def _generate_rule(self, attack: dict[str, Any]) -> dict[str, Any] | None:
        """Generate a detection rule from an observed attack pattern."""
        src = attack.get("source", "")
        attack_type = attack.get("attack_type", "")
        if not src or not attack_type:
            return None

        return {
            "rule_id": f"auto-{len(self._generated_rules) + 1}",
            "name": f"Auto-detect {attack_type} variant",
            "conditions": {
                "attack_type": attack_type,
                "min_probability": 0.3,
            },
            "actions": ["alert", "log"],
            "created_at": datetime.utcnow().isoformat(),
            "source": "self_evolving_engine",
        }

    @staticmethod
    def _attack_type_to_threshold(attack_type: str) -> str | None:
        mapping = {
            "port_scan": "port_scan_threshold",
            "brute_force": "brute_force_threshold",
            "data_exfiltration": "exfiltration_payload_threshold",
            "c2_beacon": "c2_regularity_threshold",
        }
        return mapping.get(attack_type)

    def get_thresholds(self) -> dict[str, float]:
        return dict(self._detection_thresholds)

    def get_history(self) -> list[dict]:
        return [r.to_dict() for r in self._evolution_history]

    def get_generated_rules(self) -> list[dict]:
        return list(self._generated_rules)


evolution_engine = SelfEvolvingEngine()
