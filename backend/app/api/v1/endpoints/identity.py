"""Identity-centric security endpoints."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from backend.app.services.identity.engine import identity_engine
from backend.app.services.time_prediction.engine import time_prediction_engine

router = APIRouter()


class IdentityEvent(BaseModel):
    user_id: str
    username: str = ""
    login_hour: int | None = None
    location: str | None = None
    previous_location: str | None = None
    time_since_last_login_hours: float | None = None
    new_device: bool = False
    failed_mfa: bool = False
    privilege_escalation: bool = False
    bulk_access: bool = False
    login_failed: bool = False
    concurrent_sessions: int = 0
    active_sessions: int = 1


@router.post("/assess")
async def assess_identity(event: IdentityEvent):
    return identity_engine.assess_identity(event.model_dump())


@router.get("/profiles")
async def all_profiles():
    return {"profiles": identity_engine.get_all_profiles()}


@router.get("/profiles/{user_id}")
async def get_profile(user_id: str):
    profile = identity_engine.get_profile(user_id)
    if not profile:
        return {"error": "User not found"}
    return profile


@router.get("/high-risk")
async def high_risk_users():
    return {"users": identity_engine.get_high_risk_users()}


# ── Time Prediction ───────────────────────────────────────────────────────
@router.post("/time-prediction/predict")
async def predict_attack_timing():
    return {"predictions": time_prediction_engine.predict()}


@router.get("/time-prediction/profile")
async def temporal_profile():
    return time_prediction_engine.get_temporal_profile()
