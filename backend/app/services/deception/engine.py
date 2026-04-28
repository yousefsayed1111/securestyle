"""Module 8 - Deep Fake Infrastructure (Advanced Deception).

Simulates a full company environment: fake employees, emails, chat
activity, and realistic log generation to keep attackers engaged
and extract maximum intelligence.
"""

from __future__ import annotations

import logging
import random
import uuid
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)

DEPARTMENTS = ["Engineering", "Marketing", "Finance", "HR", "Operations", "Security", "Legal"]
TITLES = [
    "Software Engineer", "Senior Engineer", "Tech Lead", "Product Manager",
    "Data Analyst", "DevOps Engineer", "Security Analyst", "VP of Engineering",
    "CTO", "System Administrator",
]
FIRST_NAMES = [
    "James", "Sarah", "Michael", "Emily", "David", "Jessica", "Robert",
    "Ashley", "William", "Amanda", "Richard", "Stephanie", "Joseph", "Nicole",
]
LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Anderson", "Taylor", "Thomas", "Moore",
]
EMAIL_SUBJECTS = [
    "Q4 Budget Review", "Sprint Planning Notes", "Security Audit Results",
    "New Hire Onboarding", "Infrastructure Migration Plan", "API v2 Launch",
    "Incident Report - Production Outage", "Team Offsite Planning",
    "Performance Review Schedule", "Vendor Contract Renewal",
]
CHAT_MESSAGES = [
    "Has anyone seen the latest deployment logs?",
    "Can someone review my PR? #4521",
    "The staging environment is down again",
    "Meeting moved to 3pm",
    "Just pushed a fix for the auth issue",
    "New vulnerability disclosed - CVE-2024-xxxxx",
    "Who has access to the production database?",
    "Reminder: security training due by Friday",
]


class FakeEmployee:
    """A simulated employee identity."""

    def __init__(self, company_domain: str = "acme-corp.internal") -> None:
        self.employee_id = uuid.uuid4().hex[:8]
        self.first_name = random.choice(FIRST_NAMES)
        self.last_name = random.choice(LAST_NAMES)
        self.email = f"{self.first_name[0].lower()}.{self.last_name.lower()}@{company_domain}"
        self.department = random.choice(DEPARTMENTS)
        self.title = random.choice(TITLES)
        self.manager_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "employee_id": self.employee_id,
            "name": f"{self.first_name} {self.last_name}",
            "email": self.email,
            "department": self.department,
            "title": self.title,
            "manager_id": self.manager_id,
        }


class DeepFakeInfrastructureEngine:
    """Generates a realistic fake company environment."""

    def __init__(self, company_domain: str = "acme-corp.internal") -> None:
        self._domain = company_domain
        self._employees: list[FakeEmployee] = []
        self._emails: list[dict[str, Any]] = []
        self._chat_messages: list[dict[str, Any]] = []
        self._logs: list[dict[str, Any]] = []

    def generate_company(self, employee_count: int = 50) -> dict[str, Any]:
        """Generate a full fake company with org chart."""
        self._employees = [FakeEmployee(self._domain) for _ in range(employee_count)]

        # Build org hierarchy
        for i, emp in enumerate(self._employees):
            if i > 0:
                emp.manager_id = self._employees[max(0, i // 3)].employee_id

        # Generate activity
        self._generate_emails(count=employee_count * 5)
        self._generate_chat(count=employee_count * 10)
        self._generate_logs(count=employee_count * 20)

        return {
            "company_domain": self._domain,
            "employee_count": len(self._employees),
            "email_count": len(self._emails),
            "chat_count": len(self._chat_messages),
            "log_count": len(self._logs),
            "departments": list({e.department for e in self._employees}),
        }

    def _generate_emails(self, count: int = 100) -> None:
        for _ in range(count):
            sender = random.choice(self._employees)
            recipient = random.choice(self._employees)
            ts = datetime.utcnow() - timedelta(hours=random.randint(0, 720))
            self._emails.append({
                "message_id": uuid.uuid4().hex[:16],
                "from": sender.email,
                "to": recipient.email,
                "subject": random.choice(EMAIL_SUBJECTS),
                "timestamp": ts.isoformat(),
                "has_attachment": random.random() < 0.2,
            })

    def _generate_chat(self, count: int = 200) -> None:
        channels = ["#general", "#engineering", "#security", "#random", "#incidents"]
        for _ in range(count):
            author = random.choice(self._employees)
            ts = datetime.utcnow() - timedelta(minutes=random.randint(0, 10080))
            self._chat_messages.append({
                "author": author.email,
                "channel": random.choice(channels),
                "message": random.choice(CHAT_MESSAGES),
                "timestamp": ts.isoformat(),
            })

    def _generate_logs(self, count: int = 500) -> None:
        log_types = ["auth", "access", "error", "audit", "system"]
        for _ in range(count):
            emp = random.choice(self._employees)
            ts = datetime.utcnow() - timedelta(minutes=random.randint(0, 10080))
            self._logs.append({
                "log_type": random.choice(log_types),
                "user": emp.email,
                "action": random.choice([
                    "login", "logout", "file_access", "api_call",
                    "config_change", "password_reset",
                ]),
                "source_ip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "timestamp": ts.isoformat(),
                "success": random.random() > 0.1,
            })

    def get_employees(self) -> list[dict]:
        return [e.to_dict() for e in self._employees]

    def get_emails(self, limit: int = 50) -> list[dict]:
        return self._emails[:limit]

    def get_chat(self, limit: int = 50) -> list[dict]:
        return self._chat_messages[:limit]

    def get_logs(self, limit: int = 100) -> list[dict]:
        return self._logs[:limit]

    def get_directory(self) -> dict[str, list[dict]]:
        """LDAP-style employee directory for attacker discovery."""
        by_dept: dict[str, list[dict]] = {}
        for emp in self._employees:
            by_dept.setdefault(emp.department, []).append(emp.to_dict())
        return by_dept


deception_engine = DeepFakeInfrastructureEngine()
