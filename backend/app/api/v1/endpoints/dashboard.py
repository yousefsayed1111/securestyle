"""Dashboard / overview endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.models.database import store
from backend.app.services.evolution.engine import evolution_engine
from backend.app.services.genetic.engine import genetic_engine
from backend.app.services.orchestrator.engine import orchestrator

router = APIRouter()


@router.get("/overview")
async def overview():
    """System-wide overview for the main dashboard."""
    counters = store.get_counters()
    return {
        "counters": counters,
        "recent_alerts": store.get_alerts(limit=20),
        "recent_predictions": store.get_predictions(limit=10),
        "recent_intents": store.get_intents(limit=10),
        "decision_history": orchestrator.decision_history[-20:],
        "evolution": {
            "thresholds": evolution_engine.get_thresholds(),
            "rules_generated": len(evolution_engine.get_generated_rules()),
        },
        "genetic": genetic_engine.get_best_strategy(),
    }


@router.get("/alerts")
async def alerts(limit: int = 50):
    return {"alerts": store.get_alerts(limit=limit)}


@router.get("/predictions")
async def predictions(limit: int = 50):
    return {"predictions": store.get_predictions(limit=limit)}


@router.get("/events")
async def events(limit: int = 100):
    return {"events": store.get_events(limit=limit)}
