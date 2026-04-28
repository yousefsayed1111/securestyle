"""Digital Twin endpoints."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from backend.app.services.digital_twin.engine import digital_twin_engine

router = APIRouter()


class SimulateRequest(BaseModel):
    attack_type: str = "port_scan"
    target_node_id: str | None = None


class TestDefenseRequest(BaseModel):
    rules: list[dict] = []


@router.post("/create")
async def create_twin():
    return digital_twin_engine.create_twin()


@router.get("/topology")
async def get_topology():
    return digital_twin_engine.get_topology()


@router.post("/simulate")
async def simulate_attack(req: SimulateRequest):
    return digital_twin_engine.simulate_attack(req.attack_type, req.target_node_id)


@router.post("/test-defense")
async def test_defense(req: TestDefenseRequest):
    return digital_twin_engine.test_defense(req.rules)


@router.get("/history")
async def simulation_history():
    return {"simulations": digital_twin_engine.get_simulation_history()}
