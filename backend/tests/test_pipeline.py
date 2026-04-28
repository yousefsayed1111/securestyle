"""Tests for the core detection pipeline."""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"


def test_ingest_synthetic():
    resp = client.post("/api/v1/pipeline/ingest", json={"generate_synthetic": 10})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ingested"] == 10


def test_full_pipeline():
    resp = client.post("/api/v1/pipeline/analyze", json={"generate_synthetic": 50})
    assert resp.status_code == 200
    data = resp.json()
    assert data["events_processed"] == 50
    assert "anomalies" in data
    assert "predictions" in data
    assert "intents" in data
    assert "decisions" in data
    assert "defense_actions" in data
    assert "evolution" in data


def test_baselines():
    # First ingest some data
    client.post("/api/v1/pipeline/analyze", json={"generate_synthetic": 20})
    resp = client.get("/api/v1/pipeline/baselines")
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_count"] > 0


def test_dashboard_overview():
    # Ensure some data exists
    client.post("/api/v1/pipeline/analyze", json={"generate_synthetic": 10})
    resp = client.get("/api/v1/dashboard/overview")
    assert resp.status_code == 200
    data = resp.json()
    assert "counters" in data
    assert "recent_alerts" in data


def test_honeynet_deploy():
    resp = client.post("/api/v1/honeynet/deploy", json={"service_type": "web"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["service_type"] == "web"
    assert "instance_id" in data


def test_honeynet_deploy_full():
    resp = client.post("/api/v1/honeynet/deploy-full")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["instances"]) == 4


def test_deception_generate():
    resp = client.post("/api/v1/honeynet/deception/generate?employee_count=10")
    assert resp.status_code == 200
    data = resp.json()
    assert data["employee_count"] == 10


def test_red_team_playbooks():
    resp = client.get("/api/v1/red-team/playbooks")
    assert resp.status_code == 200
    data = resp.json()
    assert "playbooks" in data
    assert len(data["playbooks"]) > 0


def test_red_team_run():
    resp = client.post("/api/v1/red-team/run/network_recon")
    assert resp.status_code == 200
    data = resp.json()
    assert data["simulation"]["status"] == "completed"


def test_digital_twin_create():
    resp = client.post("/api/v1/digital-twin/create")
    assert resp.status_code == 200
    data = resp.json()
    assert data["node_count"] > 0


def test_digital_twin_simulate():
    client.post("/api/v1/digital-twin/create")
    resp = client.post(
        "/api/v1/digital-twin/simulate",
        json={"attack_type": "port_scan"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "attack_path" in data


def test_genetic_evolve():
    client.post("/api/v1/defense/genetic/initialize")
    resp = client.post("/api/v1/defense/genetic/evolve")
    assert resp.status_code == 200
    data = resp.json()
    assert "generation" in data
    assert data["generation"] >= 1


def test_mtd_rotate():
    resp = client.post("/api/v1/defense/mtd/rotate-ips")
    assert resp.status_code == 200
    data = resp.json()
    assert "transformations" in data


def test_identity_assess():
    resp = client.post(
        "/api/v1/identity/assess",
        json={
            "user_id": "user-001",
            "username": "testuser",
            "new_device": True,
            "failed_mfa": True,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "risk_score" in data
    assert data["risk_score"] > 0


def test_threat_intel_generate():
    resp = client.post("/api/v1/threat-intel/generate-sample?count=10")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["generated"]) == 10


def test_threat_intel_check():
    resp = client.post(
        "/api/v1/threat-intel/check",
        json={"indicator_type": "ip", "value": "1.2.3.4"},
    )
    assert resp.status_code == 200


def test_distributed_mesh():
    resp = client.post("/api/v1/defense/distributed/generate-mesh?count=5")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_nodes"] == 5
