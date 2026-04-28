"""Threat Intelligence endpoints."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from backend.app.services.threat_intel.engine import threat_intel_engine

router = APIRouter()


class CheckRequest(BaseModel):
    indicator_type: str  # ip, domain, hash, url
    value: str


class BulkCheckRequest(BaseModel):
    items: list[dict[str, str]]


class PeerRegisterRequest(BaseModel):
    url: str
    name: str


@router.post("/check")
async def check_indicator(req: CheckRequest):
    return threat_intel_engine.check_indicator(req.indicator_type, req.value)


@router.post("/bulk-check")
async def bulk_check(req: BulkCheckRequest):
    return {"results": threat_intel_engine.bulk_check(req.items)}


@router.get("/indicators")
async def list_indicators(severity: str | None = None):
    return {"indicators": threat_intel_engine.get_indicators(severity)}


@router.get("/stats")
async def intel_stats():
    return threat_intel_engine.get_stats()


@router.post("/generate-sample")
async def generate_sample(count: int = 50):
    return {"generated": threat_intel_engine.generate_sample_indicators(count)}


@router.post("/peers/register")
async def register_peer(req: PeerRegisterRequest):
    return threat_intel_engine.register_peer(req.model_dump())


@router.post("/share")
async def share_intel():
    return threat_intel_engine.share_with_peers()
