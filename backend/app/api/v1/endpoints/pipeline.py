"""Full detection pipeline: ingest → baseline → predict → intent → decide → defend."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from backend.app.services.baseline.engine import baseline_engine
from backend.app.services.defense.engine import defense_engine
from backend.app.services.evolution.engine import evolution_engine
from backend.app.services.ingestion.engine import ingestion_engine
from backend.app.services.intent.engine import intent_engine
from backend.app.services.orchestrator.engine import orchestrator
from backend.app.services.prediction.engine import prediction_engine

router = APIRouter()


class IngestRequest(BaseModel):
    events: list[dict] = []
    generate_synthetic: int | None = None


@router.post("/ingest")
async def ingest(req: IngestRequest):
    """Ingest raw events or generate synthetic traffic."""
    if req.generate_synthetic:
        events = ingestion_engine.generate_synthetic_traffic(req.generate_synthetic)
    elif req.events:
        events = ingestion_engine.ingest(req.events)
    else:
        return {"error": "Provide events or set generate_synthetic count"}

    return {"ingested": len(events), "sample": events[:5]}


@router.post("/analyze")
async def full_pipeline(req: IngestRequest):
    """Run the full detection pipeline end-to-end."""
    # Step 1: Ingest
    if req.generate_synthetic:
        events = ingestion_engine.generate_synthetic_traffic(req.generate_synthetic)
    elif req.events:
        events = ingestion_engine.ingest(req.events)
    else:
        return {"error": "Provide events or set generate_synthetic count"}

    # Step 2: Baseline
    anomaly_scores = baseline_engine.update(events)

    # Step 3: Predict
    predictions = prediction_engine.analyze(events, anomaly_scores)

    # Step 4: Intent
    intents = intent_engine.classify(events)

    # Step 5: Decide
    decisions = orchestrator.decide(predictions, intents, anomaly_scores)

    # Step 6: Defend
    defense_actions = defense_engine.apply_decisions(decisions)

    # Step 7: Evolve
    evolution = evolution_engine.evolve([
        {"attack_type": p.predicted_attack_type, "threat_probability": p.threat_probability, "source": "pipeline"}
        for p in predictions
    ])

    return {
        "events_processed": len(events),
        "anomalies": {k: round(v, 4) for k, v in sorted(anomaly_scores.items(), key=lambda x: -x[1])[:10]},
        "predictions": [p.model_dump() for p in predictions[:10]],
        "intents": [i.model_dump() for i in intents[:10]],
        "decisions": decisions[:10],
        "defense_actions": defense_actions[:10],
        "evolution": evolution,
    }


@router.get("/baselines")
async def get_baselines():
    entities = baseline_engine.get_all_entity_ids()
    baselines = {}
    for eid in entities[:20]:
        baselines[eid] = baseline_engine.get_baseline(eid)
    return {"entity_count": len(entities), "baselines": baselines}
