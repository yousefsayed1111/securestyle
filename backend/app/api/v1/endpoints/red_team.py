"""Red Team simulation endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.services.red_team.engine import red_team_engine

router = APIRouter()


@router.get("/playbooks")
async def list_playbooks():
    return {"playbooks": red_team_engine.get_available_playbooks()}


@router.post("/run/{playbook_name}")
async def run_playbook(playbook_name: str):
    return red_team_engine.run_playbook(playbook_name)


@router.post("/run-all")
async def run_all():
    return {"results": red_team_engine.run_all_playbooks()}


@router.get("/simulations")
async def list_simulations():
    return {"simulations": red_team_engine.get_simulations()}


@router.get("/vulnerabilities")
async def list_vulnerabilities():
    return {"vulnerabilities": red_team_engine.get_all_vulnerabilities()}
