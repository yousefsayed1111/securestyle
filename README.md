# Sentinel-X Ultimate

**Predictive, Deceptive, Self-Evolving Cyber Defense System**

An autonomous cybersecurity platform that predicts attacks before they happen, understands attacker intent, deploys adaptive deception environments, and continuously evolves its defenses through genetic algorithms and self-learning.

---

## Architecture Overview

```
                    +-----------------------+
                    |   React Dashboard     |
                    |  (Explainable AI UI)  |
                    +-----------+-----------+
                                |
                    +-----------+-----------+
                    |    FastAPI Gateway     |
                    |     /api/v1/*          |
                    +-----------+-----------+
                                |
          +---------------------+---------------------+
          |                     |                     |
+---------+---------+ +---------+---------+ +---------+---------+
| DETECTION PIPELINE| |  DEFENSE SYSTEMS  | | INTELLIGENCE      |
|                   | |                   | |                   |
| 1. Ingestion      | | 10. Auto-Defense  | | 9. Attacker Intel |
| 2. Baseline       | | 11. Evolution     | | 17. Identity      |
| 3. Prediction     | | 12. Genetic Algo  | | 18. Time Predict  |
| 4. Intent Detect  | | 13. AI Red Team   | | 19. Global TI     |
| 5. Orchestrator   | | 14. Digital Twin  | |                   |
|                   | | 15. MTD           | |                   |
|                   | | 16. Distributed   | |                   |
+---------+---------+ +---------+---------+ +---------+---------+
          |                     |                     |
+---------+---------+ +---------+---------+           |
| DECEPTION         | | INFRASTRUCTURE    |           |
|                   | |                   |           |
| 6. Redirection    | | Kafka (streaming) |<----------+
| 7. Honeynet       | | Elasticsearch     |
| 8. Fake Infra     | | Docker / K8s      |
+-------------------+ +-------------------+
```

---

## Core Modules (20 Engines)

| # | Module | Description |
|---|--------|-------------|
| 1 | **Network Ingestion** | Captures PCAP/NetFlow/logs, normalizes to canonical schema, enriches with metadata |
| 2 | **Behavior Baseline** | EMA-based per-entity baselines for users, devices, and traffic flows |
| 3 | **Predictive Threat** | Pattern matching + statistical analysis for attack prediction with time-to-attack estimates |
| 4 | **Intent Detection** | MITRE ATT&CK tactic classification from behavioral evidence chains |
| 5 | **Decision Orchestrator** | Multi-signal fusion (threat + intent + anomaly) into response decisions |
| 6 | **Smart Redirection** | NAT/DNS/proxy-based attacker redirection to deception environments |
| 7 | **Adaptive Honeynet** | Dynamic honeypot fleet (Web/SSH/DB/API) with self-mutating banners |
| 8 | **Deep Fake Infra** | Full company simulation: org chart, emails, chat, logs, LDAP directory |
| 9 | **Attacker Intelligence** | Behavioral fingerprinting, tool detection, TTP extraction |
| 10 | **Automated Defense** | Auto-generates firewall rules, IDS signatures, ACL changes |
| 11 | **Self-Evolving** | Threshold adaptation and rule generation from attack analysis |
| 12 | **Genetic Security** | GA-based defense strategy evolution with fitness evaluation |
| 13 | **AI Red Team** | Autonomous attack simulation with 5 playbooks and vulnerability discovery |
| 14 | **Digital Twin** | Virtual network replica for safe attack simulation and defense testing |
| 15 | **Moving Target Defense** | Dynamic IP rotation, port shuffling, topology changes |
| 16 | **Distributed Defense** | Peer-to-peer sensor/defender mesh with threat propagation |
| 17 | **Identity Security** | Real-time user risk scoring with 10 behavioral anomaly detectors |
| 18 | **Time Prediction** | Temporal pattern analysis for attack timing forecasts |
| 19 | **Global Threat Intel** | STIX/TAXII-compatible indicator sharing across instances |
| 20 | **Explainable Dashboard** | React UI showing predictions, attack paths, and decision reasoning |

---

## Data Flow

```
Raw Traffic (PCAP/NetFlow/Syslog)
    │
    ▼
[1. Ingestion Engine] ──normalize──enrich──▶ Canonical Events
    │
    ▼
[2. Baseline Engine] ──EMA update──▶ Anomaly Scores per Entity
    │
    ├───▶ [3. Prediction Engine] ──pattern match──▶ Threat Predictions
    │         │                                       (probability, severity,
    │         │                                        time-to-attack)
    │         ▼
    ├───▶ [4. Intent Engine] ──behavioral classify──▶ Intent Classifications
    │         │                                        (MITRE ATT&CK mapping)
    │         ▼
    └───▶ [5. Decision Orchestrator] ──multi-signal fusion──▶ Response Decisions
              │
              ├─── BLOCK ──▶ [10. Defense Engine] ──▶ Firewall Rules / IDS Sigs
              ├─── ISOLATE ──▶ [10. Defense Engine] ──▶ ACL Changes
              ├─── REDIRECT ──▶ [6. Redirection] ──▶ [7. Honeynet]
              │                                          │
              │                                          ▼
              │                                   [8. Fake Infra]
              │                                          │
              │                                          ▼
              │                                   [9. Attacker Intel]
              └─── MONITOR ──▶ [11. Evolution] ──▶ Threshold Updates
                                     │
                                     ▼
                               [12. Genetic] ──▶ Strategy Evolution

Parallel Systems:
  [13. Red Team] ◄──▶ [14. Digital Twin] ──▶ Vulnerability Reports
  [15. MTD] ──▶ IP/Port/Topology Rotation
  [16. Distributed] ──▶ Peer-to-Peer Threat Propagation
  [17. Identity] ──▶ User Risk Scoring
  [18. Time Prediction] ──▶ Attack Timing Forecasts
  [19. Threat Intel] ──▶ Global Indicator Sharing
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend API | Python 3.12, FastAPI, Pydantic v2 |
| ML/AI | PyTorch, Scikit-learn (production), Statistical models (MVP) |
| Streaming | Apache Kafka |
| Search/Analytics | Elasticsearch 8.x |
| Network Analysis | Zeek, Scapy (production integrations) |
| Frontend | React 18, Vite, Recharts |
| Containerization | Docker, Docker Compose |
| Orchestration | Kubernetes |
| CI/CD | GitHub Actions |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker & Docker Compose (for full stack)

### Development Setup

```bash
# Clone
git clone https://github.com/yourusername/sentinel-x-ultimate.git
cd sentinel-x-ultimate

# Backend
pip install -e ".[dev]"
uvicorn backend.app.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

### Docker Compose (Full Stack)

```bash
cd deploy/docker
docker compose up --build
```

- **Dashboard**: http://localhost:3000
- **API Docs**: http://localhost:8000/docs
- **Health**: http://localhost:8000/health

---

## API Reference

### Full Pipeline

```bash
# Run complete detection pipeline with synthetic traffic
curl -X POST http://localhost:8000/api/v1/pipeline/analyze \
  -H "Content-Type: application/json" \
  -d '{"generate_synthetic": 200}'
```

### Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/pipeline/analyze` | POST | Run full detection pipeline |
| `/api/v1/pipeline/ingest` | POST | Ingest raw events |
| `/api/v1/dashboard/overview` | GET | System overview |
| `/api/v1/honeynet/deploy-full` | POST | Deploy full honeynet |
| `/api/v1/honeynet/deception/generate` | POST | Generate fake company |
| `/api/v1/defense/genetic/evolve` | POST | Evolve defense strategies |
| `/api/v1/defense/mtd/rotate-ips` | POST | Rotate IP addresses |
| `/api/v1/red-team/run-all` | POST | Run all attack playbooks |
| `/api/v1/digital-twin/create` | POST | Create network replica |
| `/api/v1/digital-twin/simulate` | POST | Simulate attack on twin |
| `/api/v1/identity/assess` | POST | Assess user identity risk |
| `/api/v1/threat-intel/generate-sample` | POST | Generate threat intel |
| `/api/v1/defense/distributed/generate-mesh` | POST | Deploy defense mesh |

Full interactive docs at `/docs` (Swagger UI) or `/redoc`.

---

## Folder Structure

```
sentinel-x-ultimate/
├── backend/
│   ├── app/
│   │   ├── api/v1/
│   │   │   ├── endpoints/          # API route handlers
│   │   │   │   ├── pipeline.py     # Ingest + full pipeline
│   │   │   │   ├── dashboard.py    # Overview + alerts
│   │   │   │   ├── honeynet.py     # Honeynet + deception
│   │   │   │   ├── defense.py      # Firewall, genetic, MTD, distributed
│   │   │   │   ├── red_team.py     # Attack simulation
│   │   │   │   ├── digital_twin.py # Network replica
│   │   │   │   ├── identity.py     # User risk + time prediction
│   │   │   │   └── threat_intel.py # Global threat intelligence
│   │   │   └── router.py
│   │   ├── core/
│   │   │   ├── config.py           # All configuration (env-driven)
│   │   │   └── events.py           # App lifecycle
│   │   ├── models/
│   │   │   └── database.py         # Thread-safe in-memory store
│   │   ├── schemas/
│   │   │   └── common.py           # Pydantic models & enums
│   │   ├── services/               # 19 engine modules
│   │   │   ├── ingestion/engine.py
│   │   │   ├── baseline/engine.py
│   │   │   ├── prediction/engine.py
│   │   │   ├── intent/engine.py
│   │   │   ├── orchestrator/engine.py
│   │   │   ├── redirection/engine.py
│   │   │   ├── honeynet/engine.py
│   │   │   ├── deception/engine.py
│   │   │   ├── attacker_intel/engine.py
│   │   │   ├── defense/engine.py
│   │   │   ├── evolution/engine.py
│   │   │   ├── genetic/engine.py
│   │   │   ├── red_team/engine.py
│   │   │   ├── digital_twin/engine.py
│   │   │   ├── mtd/engine.py
│   │   │   ├── distributed/engine.py
│   │   │   ├── identity/engine.py
│   │   │   ├── time_prediction/engine.py
│   │   │   └── threat_intel/engine.py
│   │   └── main.py                 # FastAPI app entry point
│   └── tests/
│       └── test_pipeline.py        # 20+ integration tests
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── dashboard/          # Main command center
│   │   │   ├── threats/            # Threat analysis view
│   │   │   ├── network/            # Network defense + MTD + genetic
│   │   │   ├── honeynet/           # Honeynet + deception + intel
│   │   │   └── redteam/            # Red team + digital twin
│   │   ├── services/api.js         # API client
│   │   ├── styles/global.css       # Dark theme cybersecurity UI
│   │   ├── App.jsx                 # Main app with sidebar nav
│   │   └── main.jsx                # Entry point
│   ├── index.html
│   ├── vite.config.js
│   └── package.json
├── deploy/
│   ├── docker/
│   │   ├── Dockerfile.backend
│   │   ├── Dockerfile.frontend
│   │   ├── docker-compose.yml      # Full stack with ES + Kafka
│   │   └── nginx.conf
│   └── kubernetes/
│       ├── namespace.yaml
│       ├── backend-deployment.yaml
│       └── frontend-deployment.yaml
├── docs/
│   └── architecture/
│       └── ARCHITECTURE.md
├── pyproject.toml
└── README.md
```

---

## AI Models Design

### MVP (Current Implementation)

The MVP uses statistical and heuristic models that run without GPU:

| Model | Approach | Purpose |
|-------|----------|---------|
| Anomaly Detection | Z-score + EMA baselines | Detect deviations from normal behavior |
| Attack Pattern Matching | Rule-based scoring | Match traffic to known attack signatures |
| Intent Classification | Feature extraction + signal matching | Map actions to MITRE ATT&CK tactics |
| Time Prediction | Interval analysis + cyclical detection | Forecast attack timing windows |
| Genetic Algorithm | Tournament selection + crossover + mutation | Evolve optimal defense strategies |

### Production Roadmap (PyTorch)

| Model | Architecture | Training Data |
|-------|-------------|---------------|
| Anomaly Detector | Variational Autoencoder (VAE) | Normal traffic baselines |
| Threat Predictor | Transformer + LSTM | Labeled attack sequences |
| Intent Classifier | BERT fine-tuned | MITRE ATT&CK mapped sessions |
| Time Forecaster | Temporal Fusion Transformer | Attack timestamp history |
| Red Team Agent | Reinforcement Learning (PPO) | Simulated network environments |

---

## Deployment Plan

### Phase 1: Development (Local)

```bash
pip install -e ".[dev]"
uvicorn backend.app.main:app --reload
```

### Phase 2: Staging (Docker Compose)

```bash
cd deploy/docker
docker compose up --build
```

### Phase 3: Production (Kubernetes)

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/backend-deployment.yaml
kubectl apply -f deploy/kubernetes/frontend-deployment.yaml
```

### Cloud Recommendations

| Component | AWS | GCP | Azure |
|-----------|-----|-----|-------|
| Compute | EKS / ECS | GKE | AKS |
| Streaming | MSK (Kafka) | Pub/Sub | Event Hubs |
| Search | OpenSearch | Elastic Cloud | Cognitive Search |
| ML | SageMaker | Vertex AI | Azure ML |
| Storage | S3 | GCS | Blob Storage |

---

## MVP Plan & Roadmap

### MVP (v1.0) - Current

- [x] 20 core engine modules with full API
- [x] Full detection pipeline (ingest -> predict -> decide -> defend)
- [x] Adaptive honeynet with self-mutating services
- [x] Fake company infrastructure generation
- [x] Genetic algorithm defense evolution
- [x] AI Red Team with 5 attack playbooks
- [x] Digital twin network simulation
- [x] Moving target defense (IP/port/topology)
- [x] Distributed P2P defense mesh
- [x] Identity risk scoring
- [x] Attack timing prediction
- [x] Global threat intelligence sharing
- [x] React dashboard with dark theme
- [x] Docker + Kubernetes deployment configs
- [x] 20+ integration tests
- [x] Interactive API documentation (Swagger)

### v1.1 - ML Enhancement

- [ ] PyTorch VAE anomaly detector
- [ ] Transformer-based threat predictor
- [ ] BERT intent classifier
- [ ] Reinforcement learning red team agent
- [ ] Model versioning and A/B testing

### v1.2 - Production Hardening

- [ ] Kafka integration for real-time streaming
- [ ] Elasticsearch persistence layer
- [ ] Prometheus + Grafana monitoring
- [ ] Rate limiting and authentication
- [ ] RBAC for dashboard access
- [ ] Audit logging

### v1.3 - Advanced Features

- [ ] PCAP file ingestion (Zeek/Scapy)
- [ ] STIX/TAXII threat intel protocol
- [ ] Automated vulnerability patching
- [ ] Attack replay system
- [ ] Self-healing infrastructure
- [ ] Threat visualization map (D3.js)

### v2.0 - Enterprise

- [ ] Multi-tenant support
- [ ] SIEM integration (Splunk, QRadar)
- [ ] SOAR workflow automation
- [ ] Compliance reporting (SOC2, ISO 27001)
- [ ] On-premise appliance packaging

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest backend/tests/ -v
```

---

## License

MIT
