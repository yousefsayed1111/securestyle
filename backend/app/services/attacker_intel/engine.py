"""Module 9 - Attacker Intelligence Engine.

Captures attacker commands, payloads, tools, and TTPs. Builds
behavioural fingerprints that uniquely identify threat actors
across sessions and campaigns.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime
from typing import Any

from backend.app.models.database import store

logger = logging.getLogger(__name__)


class AttackerFingerprint:
    """Behavioural fingerprint of a unique threat actor."""

    def __init__(self, attacker_id: str) -> None:
        self.attacker_id = attacker_id
        self.first_seen = datetime.utcnow()
        self.last_seen = datetime.utcnow()
        self.commands: list[str] = []
        self.payloads: list[str] = []
        self.tools_detected: set[str] = set()
        self.ttps: set[str] = set()
        self.source_ips: set[str] = set()
        self.targeted_services: set[str] = set()
        self.session_count: int = 0

    def update(self, data: dict[str, Any]) -> None:
        self.last_seen = datetime.utcnow()
        if cmd := data.get("command"):
            self.commands.append(cmd)
        if payload := data.get("payload"):
            self.payloads.append(payload)
        if tool := data.get("tool"):
            self.tools_detected.add(tool)
        if ttp := data.get("ttp"):
            self.ttps.add(ttp)
        if ip := data.get("source_ip"):
            self.source_ips.add(ip)
        if svc := data.get("service"):
            self.targeted_services.add(svc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attacker_id": self.attacker_id,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "command_count": len(self.commands),
            "payload_count": len(self.payloads),
            "tools": sorted(self.tools_detected),
            "ttps": sorted(self.ttps),
            "source_ips": sorted(self.source_ips),
            "targeted_services": sorted(self.targeted_services),
            "session_count": self.session_count,
            "threat_level": self._assess_threat_level(),
        }

    def _assess_threat_level(self) -> str:
        score = (
            len(self.commands) * 0.1
            + len(self.tools_detected) * 0.5
            + len(self.ttps) * 0.3
            + self.session_count * 0.2
        )
        if score > 10:
            return "critical"
        if score > 5:
            return "high"
        if score > 2:
            return "medium"
        return "low"


KNOWN_TOOLS = {
    "nmap": ["nmap", "-sS", "-sV", "-sC", "--script"],
    "metasploit": ["msfconsole", "msfvenom", "exploit/"],
    "cobalt_strike": ["beacon", "cobaltstrike", "c2profile"],
    "mimikatz": ["mimikatz", "sekurlsa", "kerberos::"],
    "bloodhound": ["bloodhound", "sharphound", "neo4j"],
    "powershell_empire": ["empire", "stager", "invoke-"],
    "hydra": ["hydra", "-l", "-P"],
    "sqlmap": ["sqlmap", "--dbs", "--tables"],
    "gobuster": ["gobuster", "dir", "-w"],
    "linpeas": ["linpeas", "linux-exploit-suggester"],
}


class AttackerIntelligenceEngine:
    """Tracks and fingerprints threat actors."""

    def __init__(self) -> None:
        self._fingerprints: dict[str, AttackerFingerprint] = {}

    def process_interaction(self, data: dict[str, Any]) -> dict[str, Any]:
        """Process a honeynet interaction and update attacker profile."""
        source_ip = data.get("source_ip", "unknown")
        attacker_id = self._resolve_attacker_id(source_ip, data)

        if attacker_id not in self._fingerprints:
            self._fingerprints[attacker_id] = AttackerFingerprint(attacker_id)

        fp = self._fingerprints[attacker_id]
        fp.update(data)

        # Auto-detect tools from commands
        command = data.get("command", "")
        for tool_name, signatures in KNOWN_TOOLS.items():
            if any(sig in command.lower() for sig in signatures):
                fp.tools_detected.add(tool_name)
                data["tool"] = tool_name

        # Persist
        store.set_fingerprint(attacker_id, fp.to_dict())

        return fp.to_dict()

    def get_fingerprint(self, attacker_id: str) -> dict[str, Any] | None:
        fp = self._fingerprints.get(attacker_id)
        return fp.to_dict() if fp else None

    def get_all_fingerprints(self) -> list[dict[str, Any]]:
        return [fp.to_dict() for fp in self._fingerprints.values()]

    def get_commands(self, attacker_id: str) -> list[str]:
        fp = self._fingerprints.get(attacker_id)
        return fp.commands if fp else []

    def _resolve_attacker_id(self, source_ip: str, data: dict) -> str:
        """Attempt to correlate IPs to the same actor via fingerprinting."""
        sig = hashlib.sha256(
            f"{data.get('user_agent', '')}"
            f"{data.get('ssh_client', '')}"
            f"{sorted(data.get('tools', []))}".encode()
        ).hexdigest()[:12]

        # Check if signature matches an existing actor
        for aid, fp in self._fingerprints.items():
            if source_ip in fp.source_ips:
                return aid

        return f"actor-{sig}"


attacker_intel_engine = AttackerIntelligenceEngine()
