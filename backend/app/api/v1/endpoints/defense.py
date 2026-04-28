"""Defense, evolution, genetic, and MTD endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.services.defense.engine import defense_engine
from backend.app.services.distributed.engine import distributed_engine
from backend.app.services.evolution.engine import evolution_engine
from backend.app.services.genetic.engine import genetic_engine
from backend.app.services.mtd.engine import mtd_engine

router = APIRouter()


# ── Firewall / Defense ─────────────────────────────────────────────────────
@router.get("/firewall-rules")
async def firewall_rules():
    return {"rules": defense_engine.get_firewall_rules()}


@router.get("/ids-signatures")
async def ids_signatures():
    return {"signatures": defense_engine.get_ids_signatures()}


# ── Evolution ──────────────────────────────────────────────────────────────
@router.get("/evolution/thresholds")
async def evolution_thresholds():
    return evolution_engine.get_thresholds()


@router.get("/evolution/history")
async def evolution_history():
    return {"history": evolution_engine.get_history()}


@router.get("/evolution/rules")
async def evolution_rules():
    return {"rules": evolution_engine.get_generated_rules()}


# ── Genetic ────────────────────────────────────────────────────────────────
@router.post("/genetic/initialize")
async def genetic_initialize():
    pop = genetic_engine.initialize_population()
    return {"initialized": len(pop), "sample": pop}


@router.post("/genetic/evolve")
async def genetic_evolve():
    return genetic_engine.evolve()


@router.get("/genetic/best")
async def genetic_best():
    return {"strategy": genetic_engine.get_best_strategy()}


# ── Moving Target Defense ──────────────────────────────────────────────────
@router.post("/mtd/rotate-ips")
async def rotate_ips():
    return {"transformations": mtd_engine.rotate_ips()}


@router.post("/mtd/shuffle-ports")
async def shuffle_ports():
    return {"transformations": mtd_engine.shuffle_ports()}


@router.post("/mtd/change-topology")
async def change_topology():
    return mtd_engine.change_topology()


@router.get("/mtd/mappings")
async def mtd_mappings():
    return mtd_engine.get_current_mappings()


# ── Distributed ────────────────────────────────────────────────────────────
@router.post("/distributed/generate-mesh")
async def generate_mesh(count: int = 10):
    return distributed_engine.generate_default_mesh(count)


@router.get("/distributed/status")
async def mesh_status():
    return distributed_engine.get_mesh_status()
