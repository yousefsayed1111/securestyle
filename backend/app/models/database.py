"""In-memory stores for the MVP (swap for a real DB in production)."""

from __future__ import annotations

import threading
from collections import defaultdict
from datetime import datetime
from typing import Any


class InMemoryStore:
    """Thread-safe in-memory data store for MVP."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[dict] = []
        self._alerts: list[dict] = []
        self._baselines: dict[str, dict] = {}
        self._predictions: list[dict] = []
        self._intents: list[dict] = []
        self._strategies: list[dict] = []
        self._identity_profiles: dict[str, dict] = {}
        self._honeynet_sessions: list[dict] = []
        self._threat_intel: list[dict] = []
        self._attack_fingerprints: dict[str, dict] = {}
        self._red_team_results: list[dict] = []
        self._counters: dict[str, int] = defaultdict(int)

    # ── Events ─────────────────────────────────────────────────────────
    def add_event(self, event: dict) -> None:
        with self._lock:
            event.setdefault("ingested_at", datetime.utcnow().isoformat())
            self._events.append(event)
            self._counters["total_events"] += 1

    def get_events(self, limit: int = 100) -> list[dict]:
        with self._lock:
            return list(reversed(self._events[-limit:]))

    # ── Alerts ─────────────────────────────────────────────────────────
    def add_alert(self, alert: dict) -> None:
        with self._lock:
            alert.setdefault("created_at", datetime.utcnow().isoformat())
            self._alerts.append(alert)
            self._counters["total_alerts"] += 1

    def get_alerts(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(reversed(self._alerts[-limit:]))

    # ── Baselines ──────────────────────────────────────────────────────
    def set_baseline(self, entity_id: str, baseline: dict) -> None:
        with self._lock:
            self._baselines[entity_id] = baseline

    def get_baseline(self, entity_id: str) -> dict | None:
        with self._lock:
            return self._baselines.get(entity_id)

    def get_all_baselines(self) -> dict[str, dict]:
        with self._lock:
            return dict(self._baselines)

    # ── Predictions ────────────────────────────────────────────────────
    def add_prediction(self, prediction: dict) -> None:
        with self._lock:
            self._predictions.append(prediction)

    def get_predictions(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(reversed(self._predictions[-limit:]))

    # ── Intent Classifications ─────────────────────────────────────────
    def add_intent(self, intent: dict) -> None:
        with self._lock:
            self._intents.append(intent)

    def get_intents(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(reversed(self._intents[-limit:]))

    # ── Defense Strategies ─────────────────────────────────────────────
    def set_strategies(self, strategies: list[dict]) -> None:
        with self._lock:
            self._strategies = strategies

    def get_strategies(self) -> list[dict]:
        with self._lock:
            return list(self._strategies)

    # ── Identity Profiles ──────────────────────────────────────────────
    def set_identity_profile(self, user_id: str, profile: dict) -> None:
        with self._lock:
            self._identity_profiles[user_id] = profile

    def get_identity_profile(self, user_id: str) -> dict | None:
        with self._lock:
            return self._identity_profiles.get(user_id)

    def get_all_identity_profiles(self) -> dict[str, dict]:
        with self._lock:
            return dict(self._identity_profiles)

    # ── Honeynet ───────────────────────────────────────────────────────
    def add_honeynet_session(self, session: dict) -> None:
        with self._lock:
            self._honeynet_sessions.append(session)

    def get_honeynet_sessions(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(reversed(self._honeynet_sessions[-limit:]))

    # ── Threat Intel ───────────────────────────────────────────────────
    def add_threat_intel(self, indicator: dict) -> None:
        with self._lock:
            self._threat_intel.append(indicator)

    def get_threat_intel(self, limit: int = 100) -> list[dict]:
        with self._lock:
            return list(reversed(self._threat_intel[-limit:]))

    # ── Attacker Fingerprints ──────────────────────────────────────────
    def set_fingerprint(self, attacker_id: str, fingerprint: dict) -> None:
        with self._lock:
            self._attack_fingerprints[attacker_id] = fingerprint

    def get_fingerprint(self, attacker_id: str) -> dict | None:
        with self._lock:
            return self._attack_fingerprints.get(attacker_id)

    def get_all_fingerprints(self) -> dict[str, dict]:
        with self._lock:
            return dict(self._attack_fingerprints)

    # ── Red Team ───────────────────────────────────────────────────────
    def add_red_team_result(self, result: dict) -> None:
        with self._lock:
            self._red_team_results.append(result)

    def get_red_team_results(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(reversed(self._red_team_results[-limit:]))

    # ── Counters ───────────────────────────────────────────────────────
    def get_counters(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._counters)

    def increment_counter(self, key: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[key] += amount


store = InMemoryStore()
