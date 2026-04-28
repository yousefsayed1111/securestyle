"""API v1 router - aggregates all endpoint modules."""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.api.v1.endpoints import (
    dashboard,
    defense,
    digital_twin,
    honeynet,
    identity,
    pipeline,
    red_team,
    threat_intel,
)

api_router = APIRouter()
api_router.include_router(pipeline.router, prefix="/pipeline", tags=["Pipeline"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(honeynet.router, prefix="/honeynet", tags=["Honeynet"])
api_router.include_router(defense.router, prefix="/defense", tags=["Defense"])
api_router.include_router(red_team.router, prefix="/red-team", tags=["Red Team"])
api_router.include_router(digital_twin.router, prefix="/digital-twin", tags=["Digital Twin"])
api_router.include_router(identity.router, prefix="/identity", tags=["Identity"])
api_router.include_router(threat_intel.router, prefix="/threat-intel", tags=["Threat Intel"])
