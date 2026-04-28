"""Module 17 - Identity-Centric Security Engine.

Assigns dynamic risk scores to users based on behavioural analysis,
detects abnormal identity patterns, and triggers defensive actions
when risk thresholds are exceeded.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from backend.app.models.database import store
from backend.app.schemas.common import IdentityRiskProfile

logger = logging.getLogger(__name__)

RISK_FACTORS = {
    "impossible_travel": 0.3,
    "unusual_hours": 0.15,
    "new_device": 0.1,
    "failed_mfa": 0.25,
    "privilege_escalation_attempt": 0.35,
    "bulk_data_access": 0.2,
    "service_account_interactive_login": 0.3,
    "dormant_account_activation": 0.2,
    "credential_stuffing_pattern": 0.25,
    "concurrent_sessions_anomaly": 0.15,
}


class IdentitySecurityEngine:
    """Real-time identity risk scoring and anomaly detection."""

    def __init__(
        self,
        risk_threshold: float = 0.75,
        lockout_threshold: float = 0.95,
    ) -> None:
        self._risk_threshold = risk_threshold
        self._lockout_threshold = lockout_threshold
        self._profiles: dict[str, IdentityRiskProfile] = {}
        self._actions_taken: list[dict[str, Any]] = []

    def assess_identity(self, user_data: dict[str, Any]) -> dict[str, Any]:
        """Assess identity risk for a user event."""
        user_id = user_data.get("user_id", "unknown")
        username = user_data.get("username", user_id)

        if user_id not in self._profiles:
            self._profiles[user_id] = IdentityRiskProfile(
                user_id=user_id, username=username,
            )

        profile = self._profiles[user_id]
        anomalies = self._detect_anomalies(user_data, profile)
        risk_score = self._calculate_risk(anomalies)

        profile.risk_score = risk_score
        profile.anomalies = anomalies
        profile.last_activity = datetime.utcnow()
        profile.sessions = user_data.get("active_sessions", profile.sessions)
        profile.failed_logins += 1 if user_data.get("login_failed") else 0

        action = self._determine_action(profile)
        store.set_identity_profile(user_id, profile.model_dump())

        result = {
            "user_id": user_id,
            "username": username,
            "risk_score": risk_score,
            "anomalies": anomalies,
            "action": action,
            "timestamp": datetime.utcnow().isoformat(),
        }

        if action != "none":
            self._actions_taken.append(result)
            store.add_alert({
                "type": "identity_risk",
                "user_id": user_id,
                "risk_score": risk_score,
                "action": action,
            })

        return result

    def _detect_anomalies(
        self, data: dict[str, Any], profile: IdentityRiskProfile,
    ) -> list[str]:
        """Detect anomalous identity behaviour."""
        anomalies: list[str] = []

        if data.get("location") and data.get("previous_location"):
            if data["location"] != data["previous_location"]:
                time_diff = data.get("time_since_last_login_hours", 24)
                if time_diff < 2:
                    anomalies.append("impossible_travel")

        hour = data.get("login_hour") or datetime.utcnow().hour
        if hour < 6 or hour > 22:
            anomalies.append("unusual_hours")

        if data.get("new_device"):
            anomalies.append("new_device")

        if data.get("failed_mfa"):
            anomalies.append("failed_mfa")

        if data.get("privilege_escalation"):
            anomalies.append("privilege_escalation_attempt")

        if data.get("bulk_access"):
            anomalies.append("bulk_data_access")

        if profile.failed_logins > 5:
            anomalies.append("credential_stuffing_pattern")

        if data.get("concurrent_sessions", 0) > 3:
            anomalies.append("concurrent_sessions_anomaly")

        return anomalies

    @staticmethod
    def _calculate_risk(anomalies: list[str]) -> float:
        """Calculate composite risk score from detected anomalies."""
        score = 0.0
        for anomaly in anomalies:
            score += RISK_FACTORS.get(anomaly, 0.1)
        return min(score, 1.0)

    def _determine_action(self, profile: IdentityRiskProfile) -> str:
        if profile.risk_score >= self._lockout_threshold:
            return "lockout"
        if profile.risk_score >= self._risk_threshold:
            return "step_up_auth"
        if profile.risk_score >= 0.5:
            return "monitor_enhanced"
        return "none"

    def get_profile(self, user_id: str) -> dict[str, Any] | None:
        profile = self._profiles.get(user_id)
        return profile.model_dump() if profile else None

    def get_all_profiles(self) -> list[dict[str, Any]]:
        return [p.model_dump() for p in self._profiles.values()]

    def get_high_risk_users(self) -> list[dict[str, Any]]:
        return [
            p.model_dump()
            for p in self._profiles.values()
            if p.risk_score >= self._risk_threshold
        ]

    def get_actions_taken(self) -> list[dict[str, Any]]:
        return list(self._actions_taken)


identity_engine = IdentitySecurityEngine()
