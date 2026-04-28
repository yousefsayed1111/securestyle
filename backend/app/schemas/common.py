"""Shared Pydantic schemas."""

from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, Field


# ── Enums ──────────────────────────────────────────────────────────────────
class ThreatSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackerIntent(str, enum.Enum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"


class DecisionAction(str, enum.Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ISOLATE = "isolate"
    REDIRECT = "redirect"
    MONITOR = "monitor"
    ALERT = "alert"


class HoneynetServiceType(str, enum.Enum):
    WEB = "web"
    SSH = "ssh"
    DATABASE = "database"
    API = "api"
    EMAIL = "email"
    FILE_SHARE = "file_share"


# ── Base Models ────────────────────────────────────────────────────────────
class NetworkEvent(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload_size: int = 0
    flags: list[str] = []
    metadata: dict = {}


class ThreatPrediction(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    threat_probability: float = Field(ge=0.0, le=1.0)
    severity: ThreatSeverity
    predicted_attack_type: str
    time_to_attack_seconds: float | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    indicators: list[str] = []
    recommended_action: DecisionAction = DecisionAction.MONITOR


class IntentClassification(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_ip: str
    intent: AttackerIntent
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = []
    kill_chain_phase: str = ""


class DefenseStrategy(BaseModel):
    strategy_id: str
    name: str
    rules: list[dict]
    fitness_score: float = 0.0
    generation: int = 0


class IdentityRiskProfile(BaseModel):
    user_id: str
    username: str
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    anomalies: list[str] = []
    last_activity: datetime = Field(default_factory=datetime.utcnow)
    sessions: int = 0
    failed_logins: int = 0


class AttackTimelinePrediction(BaseModel):
    predicted_window_start: datetime
    predicted_window_end: datetime
    confidence: float = Field(ge=0.0, le=1.0)
    attack_type: str
    target_assets: list[str] = []


class ThreatIntelIndicator(BaseModel):
    indicator_type: str  # ip, domain, hash, url
    value: str
    severity: ThreatSeverity
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: list[str] = []
    ttl_seconds: int = 86400
