"""Module 4 - Intent Detection Engine.

Classifies attacker goals using behavioral reasoning: maps sequences of
observed actions to MITRE ATT&CK tactics and provides confidence-scored
intent classifications.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from backend.app.models.database import store
from backend.app.schemas.common import AttackerIntent, IntentClassification

logger = logging.getLogger(__name__)

# Mapping of observable features to likely intents
INTENT_SIGNALS: dict[AttackerIntent, dict[str, Any]] = {
    AttackerIntent.RECONNAISSANCE: {
        "port_diversity_min": 5,
        "payload_size_max": 200,
        "protocols": {"ICMP", "DNS", "TCP"},
        "dst_port_set": {21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080},
    },
    AttackerIntent.INITIAL_ACCESS: {
        "dst_ports": {22, 3389, 445, 23},
        "repeated_connections_min": 3,
        "flags_include": ["SYN"],
    },
    AttackerIntent.CREDENTIAL_ACCESS: {
        "dst_ports": {22, 389, 636, 88, 445},
        "repeated_connections_min": 5,
    },
    AttackerIntent.LATERAL_MOVEMENT: {
        "unique_dst_min": 3,
        "internal_traffic": True,
        "dst_ports": {22, 135, 445, 3389, 5985},
    },
    AttackerIntent.EXFILTRATION: {
        "payload_size_min": 10000,
        "outbound": True,
        "dst_ports": {443, 53, 80, 8443},
    },
    AttackerIntent.COMMAND_AND_CONTROL: {
        "regular_interval": True,
        "low_payload": True,
        "dst_ports": {443, 8443, 53, 8080},
    },
    AttackerIntent.DISCOVERY: {
        "protocol_diversity_min": 3,
        "dst_ports": {53, 135, 139, 445, 389},
    },
    AttackerIntent.EXECUTION: {
        "dst_ports": {445, 135, 5985, 5986},
        "payload_size_min": 500,
    },
}


class IntentDetectionEngine:
    """Classify attacker intent from network event sequences."""

    def classify(self, events: list[dict[str, Any]]) -> list[IntentClassification]:
        """Classify intent for each unique source IP in the event batch."""
        by_source: dict[str, list[dict]] = defaultdict(list)
        for e in events:
            by_source[e.get("src_ip", "unknown")].append(e)

        results: list[IntentClassification] = []
        for src_ip, src_events in by_source.items():
            features = self._extract_features(src_events)
            intent, confidence, evidence = self._match_intent(features)
            classification = IntentClassification(
                source_ip=src_ip,
                intent=intent,
                confidence=confidence,
                evidence=evidence,
                kill_chain_phase=self._intent_to_kill_chain(intent),
            )
            results.append(classification)
            store.add_intent(classification.model_dump())

        return results

    def _extract_features(self, events: list[dict]) -> dict[str, Any]:
        """Extract behavioural features from a set of events."""
        ports = {e.get("dst_port", 0) for e in events}
        protocols = {e.get("protocol", "TCP") for e in events}
        payloads = [e.get("payload_size", 0) for e in events]
        dst_ips = {e.get("dst_ip", "") for e in events}
        flags_all: list[str] = []
        for e in events:
            flags_all.extend(e.get("flags", []))

        avg_payload = sum(payloads) / max(len(payloads), 1)
        internal = all(
            ip.startswith(("10.", "192.168.", "172."))
            for ip in dst_ips
            if ip
        )

        return {
            "port_count": len(ports),
            "ports": ports,
            "protocol_count": len(protocols),
            "protocols": protocols,
            "avg_payload": avg_payload,
            "max_payload": max(payloads, default=0),
            "min_payload": min(payloads, default=0),
            "event_count": len(events),
            "unique_dst": len(dst_ips),
            "flags": set(flags_all),
            "internal": internal,
        }

    def _match_intent(
        self, features: dict[str, Any]
    ) -> tuple[AttackerIntent, float, list[str]]:
        """Score each intent and return the best match."""
        best_intent = AttackerIntent.RECONNAISSANCE
        best_score = 0.0
        best_evidence: list[str] = []

        for intent, signals in INTENT_SIGNALS.items():
            score = 0.0
            evidence: list[str] = []
            checks = 0

            if "port_diversity_min" in signals:
                checks += 1
                if features["port_count"] >= signals["port_diversity_min"]:
                    score += 1
                    evidence.append(f"port_diversity={features['port_count']}")

            if "dst_ports" in signals:
                checks += 1
                overlap = features["ports"] & signals["dst_ports"]
                if overlap:
                    score += len(overlap) / len(signals["dst_ports"])
                    evidence.append(f"matching_ports={sorted(overlap)}")

            if "repeated_connections_min" in signals:
                checks += 1
                if features["event_count"] >= signals["repeated_connections_min"]:
                    score += 1
                    evidence.append(f"connection_count={features['event_count']}")

            if "unique_dst_min" in signals:
                checks += 1
                if features["unique_dst"] >= signals["unique_dst_min"]:
                    score += 1
                    evidence.append(f"unique_destinations={features['unique_dst']}")

            if "payload_size_min" in signals:
                checks += 1
                if features["avg_payload"] >= signals["payload_size_min"]:
                    score += 1
                    evidence.append(f"avg_payload={features['avg_payload']:.0f}")

            if "payload_size_max" in signals:
                checks += 1
                if features["avg_payload"] <= signals["payload_size_max"]:
                    score += 1
                    evidence.append(f"low_payload={features['avg_payload']:.0f}")

            if "protocol_diversity_min" in signals:
                checks += 1
                if features["protocol_count"] >= signals["protocol_diversity_min"]:
                    score += 1
                    evidence.append(f"protocol_diversity={features['protocol_count']}")

            if "internal_traffic" in signals and signals["internal_traffic"]:
                checks += 1
                if features["internal"]:
                    score += 1
                    evidence.append("internal_traffic=true")

            if "outbound" in signals and signals["outbound"]:
                checks += 1
                if not features["internal"]:
                    score += 1
                    evidence.append("outbound_traffic=true")

            normalised = score / max(checks, 1)
            if normalised > best_score:
                best_score = normalised
                best_intent = intent
                best_evidence = evidence

        return best_intent, round(best_score, 4), best_evidence

    @staticmethod
    def _intent_to_kill_chain(intent: AttackerIntent) -> str:
        mapping = {
            AttackerIntent.RECONNAISSANCE: "reconnaissance",
            AttackerIntent.INITIAL_ACCESS: "weaponization/delivery",
            AttackerIntent.EXECUTION: "exploitation",
            AttackerIntent.PERSISTENCE: "installation",
            AttackerIntent.PRIVILEGE_ESCALATION: "exploitation",
            AttackerIntent.DEFENSE_EVASION: "exploitation",
            AttackerIntent.CREDENTIAL_ACCESS: "exploitation",
            AttackerIntent.DISCOVERY: "reconnaissance",
            AttackerIntent.LATERAL_MOVEMENT: "lateral_movement",
            AttackerIntent.COLLECTION: "collection",
            AttackerIntent.EXFILTRATION: "actions_on_objectives",
            AttackerIntent.COMMAND_AND_CONTROL: "command_and_control",
            AttackerIntent.IMPACT: "actions_on_objectives",
        }
        return mapping.get(intent, "unknown")


intent_engine = IntentDetectionEngine()
