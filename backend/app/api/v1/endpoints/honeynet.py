"""Honeynet & deception endpoints."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from backend.app.schemas.common import HoneynetServiceType
from backend.app.services.deception.engine import deception_engine
from backend.app.services.honeynet.engine import honeynet_engine
from backend.app.services.redirection.engine import redirection_engine

router = APIRouter()


class DeployRequest(BaseModel):
    service_type: HoneynetServiceType = HoneynetServiceType.WEB
    target_ip: str | None = None


class RedirectRequest(BaseModel):
    source_ip: str
    original_dst: str


@router.post("/deploy")
async def deploy_service(req: DeployRequest):
    instance = honeynet_engine.deploy_service(req.service_type, req.target_ip)
    return instance.to_dict()


@router.post("/deploy-full")
async def deploy_full_environment(target_ip: str | None = None):
    return {"instances": honeynet_engine.deploy_full_environment(target_ip)}


@router.get("/instances")
async def list_instances():
    return {"instances": honeynet_engine.get_all_instances()}


@router.post("/redirect")
async def redirect_attacker(req: RedirectRequest):
    return redirection_engine.redirect(req.source_ip, req.original_dst)


@router.get("/redirections")
async def active_redirections():
    return {"rules": redirection_engine.get_active_rules()}


@router.post("/deception/generate")
async def generate_company(employee_count: int = 50):
    return deception_engine.generate_company(employee_count)


@router.get("/deception/directory")
async def get_directory():
    return deception_engine.get_directory()


@router.get("/deception/emails")
async def get_emails(limit: int = 50):
    return {"emails": deception_engine.get_emails(limit)}


@router.get("/deception/chat")
async def get_chat(limit: int = 50):
    return {"messages": deception_engine.get_chat(limit)}


@router.post("/mutate")
async def mutate_honeynet():
    count = honeynet_engine.mutate_all()
    return {"mutated_instances": count}
