"""Module 13 - AI Red Team Engine.

Simulates real attacker behaviour autonomously to discover vulnerabilities
in the network. Runs attack playbooks (recon, exploit, pivot, exfil) and
reports findings to the defense system.
"""

from __future__ import annotations

import logging
import random
import uuid
from datetime import datetime
from typing import Any

from backend.app.models.database import store

logger = logging.getLogger(__name__)

ATTACK_PLAYBOOKS = {
    "network_recon": {
        "description": "Discover live hosts, open ports, and services",
        "steps": [
            {"action": "ping_sweep", "target": "10.0.0.0/24"},
            {"action": "port_scan", "ports": "top-1000"},
            {"action": "service_enum", "focus": "version_detection"},
            {"action": "os_fingerprint", "method": "tcp_stack"},
        ],
    },
    "credential_attack": {
        "description": "Attempt credential-based attacks",
        "steps": [
            {"action": "password_spray", "targets": ["ssh", "rdp", "smb"]},
            {"action": "brute_force", "service": "ssh", "wordlist": "rockyou-top10k"},
            {"action": "kerberoast", "domain": "internal.local"},
            {"action": "credential_dump", "method": "mimikatz"},
        ],
    },
    "web_exploit": {
        "description": "Test web application vulnerabilities",
        "steps": [
            {"action": "directory_enum", "wordlist": "common.txt"},
            {"action": "sqli_test", "params": ["id", "search", "user"]},
            {"action": "xss_test", "contexts": ["reflected", "stored"]},
            {"action": "ssrf_test", "targets": ["metadata", "internal_api"]},
        ],
    },
    "lateral_movement": {
        "description": "Attempt to move laterally through the network",
        "steps": [
            {"action": "pass_the_hash", "protocol": "smb"},
            {"action": "psexec", "target": "file_server"},
            {"action": "wmi_exec", "target": "workstation"},
            {"action": "ssh_pivot", "target": "jump_host"},
        ],
    },
    "data_exfiltration": {
        "description": "Simulate data theft",
        "steps": [
            {"action": "find_sensitive_data", "patterns": ["*.pem", "*.env", "*.conf"]},
            {"action": "compress", "method": "tar+gz"},
            {"action": "encrypt", "algorithm": "aes-256"},
            {"action": "exfiltrate", "channels": ["dns", "https", "icmp"]},
        ],
    },
}


class RedTeamSimulation:
    """A single red team simulation run."""

    def __init__(self, playbook_name: str) -> None:
        self.sim_id = uuid.uuid4().hex[:12]
        self.playbook = playbook_name
        self.started_at = datetime.utcnow()
        self.completed_at: datetime | None = None
        self.steps_completed: list[dict[str, Any]] = []
        self.vulnerabilities_found: list[dict[str, Any]] = []
        self.status = "running"

    def to_dict(self) -> dict[str, Any]:
        return {
            "sim_id": self.sim_id,
            "playbook": self.playbook,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
            "steps_completed": len(self.steps_completed),
            "vulnerabilities_found": len(self.vulnerabilities_found),
        }


class AIRedTeamEngine:
    """Autonomous attack simulation engine."""

    def __init__(self) -> None:
        self._simulations: list[RedTeamSimulation] = []

    def run_playbook(self, playbook_name: str) -> dict[str, Any]:
        """Execute an attack playbook and return findings."""
        if playbook_name not in ATTACK_PLAYBOOKS:
            return {"error": f"Unknown playbook: {playbook_name}"}

        playbook = ATTACK_PLAYBOOKS[playbook_name]
        sim = RedTeamSimulation(playbook_name)

        for step in playbook["steps"]:
            result = self._execute_step(step)
            sim.steps_completed.append(result)
            if result.get("vulnerability_found"):
                vuln = {
                    "type": result["vulnerability_type"],
                    "severity": result["severity"],
                    "description": result["description"],
                    "affected_asset": result.get("target", "unknown"),
                    "playbook": playbook_name,
                    "step": step["action"],
                }
                sim.vulnerabilities_found.append(vuln)

        sim.completed_at = datetime.utcnow()
        sim.status = "completed"
        self._simulations.append(sim)
        store.add_red_team_result(sim.to_dict())

        return {
            "simulation": sim.to_dict(),
            "vulnerabilities": sim.vulnerabilities_found,
            "playbook_description": playbook["description"],
        }

    def run_all_playbooks(self) -> list[dict[str, Any]]:
        """Run all available playbooks."""
        return [self.run_playbook(name) for name in ATTACK_PLAYBOOKS]

    def _execute_step(self, step: dict[str, Any]) -> dict[str, Any]:
        """Simulate executing an attack step (returns synthetic results)."""
        action = step.get("action", "unknown")
        vulnerability_prob = random.random()

        result: dict[str, Any] = {
            "action": action,
            "timestamp": datetime.utcnow().isoformat(),
            "success": random.random() > 0.3,
            "duration_ms": random.randint(100, 5000),
        }

        if vulnerability_prob > 0.7:
            result["vulnerability_found"] = True
            result["vulnerability_type"] = self._infer_vuln_type(action)
            result["severity"] = random.choice(["low", "medium", "high", "critical"])
            result["description"] = f"Potential vulnerability found during {action}"
            result["target"] = step.get("target", step.get("service", "unknown"))
        else:
            result["vulnerability_found"] = False

        return result

    @staticmethod
    def _infer_vuln_type(action: str) -> str:
        mapping = {
            "port_scan": "open_port",
            "password_spray": "weak_credentials",
            "brute_force": "weak_credentials",
            "sqli_test": "sql_injection",
            "xss_test": "cross_site_scripting",
            "ssrf_test": "server_side_request_forgery",
            "pass_the_hash": "credential_reuse",
            "find_sensitive_data": "data_exposure",
            "credential_dump": "credential_exposure",
        }
        return mapping.get(action, "misconfiguration")

    def get_simulations(self) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self._simulations]

    def get_all_vulnerabilities(self) -> list[dict[str, Any]]:
        vulns = []
        for sim in self._simulations:
            vulns.extend(sim.vulnerabilities_found)
        return vulns

    def get_available_playbooks(self) -> dict[str, str]:
        return {name: pb["description"] for name, pb in ATTACK_PLAYBOOKS.items()}


red_team_engine = AIRedTeamEngine()
