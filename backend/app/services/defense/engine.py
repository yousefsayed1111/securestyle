"""Module 10 - Automated Defense System.

Auto-updates firewall rules, IDS/IPS signatures, and access control
policies in response to detected threats and orchestrator decisions.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

from backend.app.models.database import store

logger = logging.getLogger(__name__)


class FirewallRule:
    def __init__(
        self,
        action: str,
        source: str,
        destination: str = "any",
        port: int | None = None,
        protocol: str = "any",
        reason: str = "",
    ) -> None:
        self.rule_id = uuid.uuid4().hex[:12]
        self.action = action  # block | allow | rate_limit
        self.source = source
        self.destination = destination
        self.port = port
        self.protocol = protocol
        self.reason = reason
        self.created_at = datetime.utcnow()
        self.active = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "action": self.action,
            "source": self.source,
            "destination": self.destination,
            "port": self.port,
            "protocol": self.protocol,
            "reason": self.reason,
            "created_at": self.created_at.isoformat(),
            "active": self.active,
        }


class AutomatedDefenseEngine:
    """Automatically applies defensive measures based on orchestrator decisions."""

    def __init__(self) -> None:
        self._firewall_rules: list[FirewallRule] = []
        self._ids_signatures: list[dict[str, Any]] = []
        self._acl_changes: list[dict[str, Any]] = []

    def apply_decisions(self, decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert orchestrator decisions into defensive actions."""
        actions_taken: list[dict[str, Any]] = []

        for decision in decisions:
            action = decision.get("action", "monitor")
            src = decision.get("source_ip", "unknown")

            if action == "block":
                rule = self._add_firewall_rule("block", src, reason=decision.get("reasoning", ""))
                actions_taken.append({"type": "firewall_block", "rule": rule.to_dict()})

            elif action == "isolate":
                rule = self._add_firewall_rule("block", src, reason="isolation")
                self._add_acl_change(src, "deny_all")
                actions_taken.append({"type": "isolate", "rule": rule.to_dict()})

            elif action == "redirect":
                actions_taken.append({
                    "type": "redirect_to_honeynet",
                    "source": src,
                    "status": "redirected",
                })

            elif action == "alert":
                sig = self._add_ids_signature(src, decision.get("attack_type", ""))
                actions_taken.append({"type": "ids_signature", "signature": sig})

            store.increment_counter(f"defense_action_{action}")

        return actions_taken

    def _add_firewall_rule(
        self, action: str, source: str, reason: str = ""
    ) -> FirewallRule:
        rule = FirewallRule(action=action, source=source, reason=reason)
        self._firewall_rules.append(rule)
        logger.info("Firewall rule added: %s %s (%s)", action, source, reason)
        return rule

    def _add_ids_signature(self, source: str, attack_type: str) -> dict[str, Any]:
        sig = {
            "sig_id": uuid.uuid4().hex[:12],
            "source": source,
            "attack_type": attack_type,
            "created_at": datetime.utcnow().isoformat(),
        }
        self._ids_signatures.append(sig)
        return sig

    def _add_acl_change(self, entity: str, policy: str) -> None:
        self._acl_changes.append({
            "entity": entity,
            "policy": policy,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def get_firewall_rules(self) -> list[dict]:
        return [r.to_dict() for r in self._firewall_rules if r.active]

    def get_ids_signatures(self) -> list[dict]:
        return list(self._ids_signatures)


defense_engine = AutomatedDefenseEngine()
