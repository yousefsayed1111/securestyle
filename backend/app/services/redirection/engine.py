"""Module 6 - Smart Redirection Engine.

Seamlessly redirects attackers from production assets into the honeynet
deception environment using network-level manipulation (NAT rules,
DNS redirection, proxy insertion).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

from backend.app.models.database import store

logger = logging.getLogger(__name__)


class RedirectionRule:
    """Represents a single traffic redirection rule."""

    def __init__(
        self,
        source_ip: str,
        original_dst: str,
        honeynet_dst: str,
        method: str = "nat",
    ) -> None:
        self.rule_id = uuid.uuid4().hex[:12]
        self.source_ip = source_ip
        self.original_dst = original_dst
        self.honeynet_dst = honeynet_dst
        self.method = method  # nat | dns | proxy
        self.created_at = datetime.utcnow()
        self.active = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "source_ip": self.source_ip,
            "original_dst": self.original_dst,
            "honeynet_dst": self.honeynet_dst,
            "method": self.method,
            "created_at": self.created_at.isoformat(),
            "active": self.active,
        }


class SmartRedirectionEngine:
    """Manages attacker redirection into deception environments."""

    def __init__(self) -> None:
        self._rules: dict[str, RedirectionRule] = {}

    def redirect(
        self,
        source_ip: str,
        original_dst: str,
        honeynet_subnet: str = "10.99.0.0/16",
    ) -> dict[str, Any]:
        """Create a redirection rule for a given attacker."""
        # Assign a honeynet IP within the deception subnet
        honeynet_ip = self._allocate_honeynet_ip(honeynet_subnet)
        rule = RedirectionRule(
            source_ip=source_ip,
            original_dst=original_dst,
            honeynet_dst=honeynet_ip,
            method=self._select_method(source_ip),
        )
        self._rules[rule.rule_id] = rule

        logger.info(
            "Redirecting %s → %s (was %s) via %s",
            source_ip,
            honeynet_ip,
            original_dst,
            rule.method,
        )

        session_data = {
            "session_id": rule.rule_id,
            "attacker_ip": source_ip,
            "honeynet_ip": honeynet_ip,
            "started_at": datetime.utcnow().isoformat(),
            "method": rule.method,
            "status": "active",
        }
        store.add_honeynet_session(session_data)
        return rule.to_dict()

    def deactivate(self, rule_id: str) -> bool:
        rule = self._rules.get(rule_id)
        if rule:
            rule.active = False
            return True
        return False

    def get_active_rules(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._rules.values() if r.active]

    def _allocate_honeynet_ip(self, subnet: str) -> str:
        """Allocate the next available IP in the honeynet subnet."""
        base = subnet.split("/")[0].rsplit(".", 1)[0]
        used = {r.honeynet_dst for r in self._rules.values()}
        for i in range(1, 254):
            for j in range(1, 254):
                candidate = f"{base}.{i}.{j}"
                if candidate not in used:
                    return candidate
        return f"{base}.1.1"

    @staticmethod
    def _select_method(source_ip: str) -> str:
        """Select redirection method based on source characteristics."""
        # In production, this would consider the network topology
        return "nat"


redirection_engine = SmartRedirectionEngine()
