"""Module 7 - Adaptive Honeynet (Deception System).

Generates and manages dynamic honeypot services: fake web servers,
databases, SSH endpoints, APIs, and credential stores. Services
self-mutate to remain realistic and unpredictable.
"""

from __future__ import annotations

import logging
import random
import uuid
from datetime import datetime
from typing import Any

from backend.app.schemas.common import HoneynetServiceType

logger = logging.getLogger(__name__)

FAKE_BANNERS = {
    HoneynetServiceType.SSH: [
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        "SSH-2.0-OpenSSH_9.3p1 Debian-1",
        "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u2",
    ],
    HoneynetServiceType.WEB: [
        "Apache/2.4.52 (Ubuntu)",
        "nginx/1.22.1",
        "Microsoft-IIS/10.0",
    ],
    HoneynetServiceType.DATABASE: [
        "MySQL 8.0.35",
        "PostgreSQL 15.4",
        "Microsoft SQL Server 2019",
    ],
    HoneynetServiceType.API: [
        "Express/4.18.2",
        "FastAPI/0.104.1",
        "Spring Boot/3.2.0",
    ],
}

FAKE_CREDENTIALS = [
    ("admin", "admin123"),
    ("root", "toor"),
    ("deploy", "s3cur3-d3pl0y!"),
    ("backup_svc", "Backup2024!"),
    ("jenkins", "j3nk1ns_p@ss"),
]

FAKE_DATA_TEMPLATES = {
    "users_table": [
        {"id": 1, "email": "admin@acme-corp.internal", "role": "admin"},
        {"id": 2, "email": "j.smith@acme-corp.internal", "role": "engineer"},
        {"id": 3, "email": "a.jones@acme-corp.internal", "role": "analyst"},
    ],
    "config_file": {
        "database": {"host": "db-primary.internal", "port": 5432},
        "api_key": "sk-fake-0123456789abcdef",
        "aws_region": "us-east-1",
    },
}


class HoneynetInstance:
    """A single honeypot service instance."""

    def __init__(
        self,
        service_type: HoneynetServiceType,
        ip: str,
        port: int,
    ) -> None:
        self.instance_id = uuid.uuid4().hex[:12]
        self.service_type = service_type
        self.ip = ip
        self.port = port
        self.banner = random.choice(FAKE_BANNERS.get(service_type, ["Unknown Service"]))
        self.credentials = random.sample(FAKE_CREDENTIALS, k=min(3, len(FAKE_CREDENTIALS)))
        self.created_at = datetime.utcnow()
        self.interactions: list[dict[str, Any]] = []
        self.active = True

    def record_interaction(self, data: dict[str, Any]) -> None:
        data["timestamp"] = datetime.utcnow().isoformat()
        data["instance_id"] = self.instance_id
        self.interactions.append(data)

    def mutate(self) -> None:
        """Change banner and credentials to remain unpredictable."""
        banners = FAKE_BANNERS.get(self.service_type, [])
        if banners:
            self.banner = random.choice(banners)
        self.credentials = random.sample(FAKE_CREDENTIALS, k=min(3, len(FAKE_CREDENTIALS)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "service_type": self.service_type.value,
            "ip": self.ip,
            "port": self.port,
            "banner": self.banner,
            "created_at": self.created_at.isoformat(),
            "interaction_count": len(self.interactions),
            "active": self.active,
        }


class AdaptiveHoneynetEngine:
    """Manages a fleet of dynamic honeypot instances."""

    def __init__(self, subnet: str = "10.99.0.0/16", max_instances: int = 50) -> None:
        self._subnet_base = subnet.split("/")[0].rsplit(".", 2)[0]
        self._max = max_instances
        self._instances: dict[str, HoneynetInstance] = {}

    def deploy_service(
        self,
        service_type: HoneynetServiceType,
        target_ip: str | None = None,
    ) -> HoneynetInstance:
        """Deploy a new honeypot service."""
        ip = target_ip or self._next_ip()
        port = self._default_port(service_type)
        instance = HoneynetInstance(service_type, ip, port)
        self._instances[instance.instance_id] = instance
        logger.info("Deployed %s honeypot at %s:%d", service_type.value, ip, port)
        return instance

    def deploy_full_environment(self, target_ip: str | None = None) -> list[dict]:
        """Deploy a realistic multi-service environment."""
        services = [
            HoneynetServiceType.WEB,
            HoneynetServiceType.SSH,
            HoneynetServiceType.DATABASE,
            HoneynetServiceType.API,
        ]
        deployed = []
        for svc in services:
            inst = self.deploy_service(svc, target_ip)
            deployed.append(inst.to_dict())
        return deployed

    def record_interaction(self, instance_id: str, data: dict) -> bool:
        inst = self._instances.get(instance_id)
        if inst:
            inst.record_interaction(data)
            return True
        return False

    def mutate_all(self) -> int:
        """Mutate all active instances to stay realistic."""
        count = 0
        for inst in self._instances.values():
            if inst.active:
                inst.mutate()
                count += 1
        return count

    def get_all_instances(self) -> list[dict[str, Any]]:
        return [i.to_dict() for i in self._instances.values()]

    def get_interactions(self, instance_id: str) -> list[dict]:
        inst = self._instances.get(instance_id)
        return inst.interactions if inst else []

    def get_fake_data(self, data_type: str = "users_table") -> Any:
        return FAKE_DATA_TEMPLATES.get(data_type, {})

    def _next_ip(self) -> str:
        used = {i.ip for i in self._instances.values()}
        for a in range(1, 254):
            for b in range(1, 254):
                ip = f"{self._subnet_base}.{a}.{b}"
                if ip not in used:
                    return ip
        return f"{self._subnet_base}.1.1"

    @staticmethod
    def _default_port(service_type: HoneynetServiceType) -> int:
        return {
            HoneynetServiceType.WEB: 80,
            HoneynetServiceType.SSH: 22,
            HoneynetServiceType.DATABASE: 5432,
            HoneynetServiceType.API: 8080,
            HoneynetServiceType.EMAIL: 25,
            HoneynetServiceType.FILE_SHARE: 445,
        }.get(service_type, 8080)


honeynet_engine = AdaptiveHoneynetEngine()
