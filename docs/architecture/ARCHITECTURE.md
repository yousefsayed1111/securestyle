# Sentinel-X Ultimate - Detailed System Architecture

## 1. System Architecture

Sentinel-X Ultimate follows a **microservices-oriented monolith** architecture for the MVP,
designed to be decomposed into independent services as the system scales.

### Design Principles

- **Defense in Depth**: Multiple independent detection layers working in parallel
- **Assume Breach**: The honeynet/deception layer assumes attackers will penetrate defenses
- **Autonomous Response**: Decisions are made algorithmically with human-in-the-loop override
- **Continuous Evolution**: The system learns from every interaction and improves automatically

### Layered Architecture

```
┌────────────────────────────────────────────────────────────┐
│                   PRESENTATION LAYER                       │
│  React Dashboard | REST API | WebSocket (planned)          │
├────────────────────────────────────────────────────────────┤
│                   API GATEWAY LAYER                        │
│  FastAPI | Authentication | Rate Limiting | Routing        │
├────────────────────────────────────────────────────────────┤
│                   SERVICE LAYER                            │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐       │
│  │  Detection    │ │  Response    │ │  Intelligence │       │
│  │  Pipeline     │ │  Systems     │ │  Systems      │       │
│  │              │ │              │ │               │       │
│  │ Ingestion    │ │ Orchestrator │ │ Attacker Intel│       │
│  │ Baseline     │ │ Defense      │ │ Identity      │       │
│  │ Prediction   │ │ Redirection  │ │ Time Predict  │       │
│  │ Intent       │ │ Honeynet     │ │ Threat Intel  │       │
│  │              │ │ Evolution    │ │               │       │
│  │              │ │ Genetic      │ │               │       │
│  │              │ │ Red Team     │ │               │       │
│  │              │ │ Digital Twin │ │               │       │
│  │              │ │ MTD          │ │               │       │
│  │              │ │ Distributed  │ │               │       │
│  └──────────────┘ └──────────────┘ └──────────────┘       │
├────────────────────────────────────────────────────────────┤
│                   DATA LAYER                               │
│  In-Memory Store (MVP) | Elasticsearch | Kafka | Redis     │
├────────────────────────────────────────────────────────────┤
│                   INFRASTRUCTURE LAYER                     │
│  Docker | Kubernetes | Monitoring | Logging                │
└────────────────────────────────────────────────────────────┘
```

## 2. Detection Pipeline Deep Dive

### Stage 1: Ingestion

The ingestion engine accepts heterogeneous input formats and normalises them:

- **PCAP**: Raw packet captures parsed for header fields
- **NetFlow/IPFIX**: Flow records with aggregate statistics
- **Syslog**: System and application logs
- **API**: Direct event submission via REST

Each event is enriched with:
- Directional classification (inbound/outbound)
- Event hash for deduplication
- Timestamp normalisation to UTC

### Stage 2: Baseline

Per-entity baselines track:
- **Payload size distribution** (mean, variance via EMA)
- **Port usage patterns** (set of observed ports)
- **Protocol distribution** (counts by protocol)
- **Temporal patterns** (24-hour histogram)

The EMA smoothing factor (alpha=0.05) allows gradual adaptation to legitimate
changes while maintaining sensitivity to sudden deviations.

### Stage 3: Prediction

Five attack pattern detectors run in parallel:

| Pattern | Key Feature | Threshold |
|---------|------------|-----------|
| Port Scan | Port diversity per source | 10 unique ports |
| Brute Force | Repeated auth-port connections | 5 attempts |
| Data Exfiltration | Aggregate payload size | 50KB total |
| C2 Beacon | Connection interval regularity | 0.9 regularity score |
| Lateral Movement | Unique destination count | 5 unique targets |

Scores are combined with anomaly scores using a weighted fusion:
`combined = 0.6 * pattern_score + 0.4 * anomaly_score`

### Stage 4: Intent Classification

Maps observable behaviors to MITRE ATT&CK tactics using a feature extraction
pipeline that considers:

- Port diversity and specific port usage
- Payload characteristics
- Traffic directionality
- Protocol diversity
- Connection patterns

### Stage 5: Decision Orchestration

Multi-factor decision matrix:

| Severity | Intent Impact | Anomaly | Action |
|----------|--------------|---------|--------|
| Critical | High (exfil, C2) | Any | REDIRECT to honeynet |
| Critical | Any | Any | ISOLATE |
| High | Any | > 0.8 | REDIRECT |
| High | Any | < 0.8 | BLOCK |
| Medium | Any | High confidence | BLOCK |
| Medium | Any | Low confidence | ALERT |
| Low | Any | Any | MONITOR |

## 3. Honeynet Architecture

```
                    Attacker
                       │
                       ▼
              ┌────────────────┐
              │  Redirection   │
              │  Engine (NAT)  │
              └────────┬───────┘
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
    ┌─────────┐  ┌─────────┐  ┌─────────┐
    │ Web     │  │ SSH     │  │ DB      │
    │ Honeypot│  │ Honeypot│  │ Honeypot│
    │ :80/443 │  │ :22     │  │ :5432   │
    └────┬────┘  └────┬────┘  └────┬────┘
         │            │            │
         ▼            ▼            ▼
    ┌──────────────────────────────────┐
    │     Deep Fake Infrastructure     │
    │  ┌──────┐ ┌──────┐ ┌─────────┐  │
    │  │Emails│ │ Chat │ │  LDAP   │  │
    │  │      │ │      │ │Directory│  │
    │  └──────┘ └──────┘ └─────────┘  │
    └──────────────┬───────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────┐
    │    Attacker Intelligence Engine  │
    │  - Command logging              │
    │  - Payload capture              │
    │  - Tool identification          │
    │  - Behavioral fingerprinting    │
    └──────────────────────────────────┘
```

The honeynet self-mutates periodically:
- Banners change to match real-world software versions
- Credentials rotate to prevent fingerprinting
- Fake data evolves to maintain freshness

## 4. Digital Twin Design

The digital twin creates a full virtual replica of the production network:

```
Production Network              Digital Twin
┌─────────────────┐            ┌─────────────────┐
│  Firewall       │──clone──▶  │  Virtual FW     │
│  Router         │            │  Virtual Router  │
│  Web Servers    │            │  Virtual Web     │
│  DB Servers     │            │  Virtual DB      │
│  Workstations   │            │  Virtual WS      │
└─────────────────┘            └─────────────────┘
                                       │
                                       ▼
                               ┌───────────────┐
                               │ Attack        │
                               │ Simulation    │
                               │ Engine        │
                               └───────┬───────┘
                                       │
                                       ▼
                               ┌───────────────┐
                               │ Impact        │
                               │ Analysis      │
                               │ Report        │
                               └───────────────┘
```

The twin supports:
- **Attack simulation**: Test any attack type against the virtual network
- **Defense testing**: Validate new rules before deploying to production
- **Impact analysis**: Measure blast radius of potential compromises
- **What-if scenarios**: Test topology changes and policy updates

## 5. Genetic Algorithm Design

```
Generation 0                Generation N
┌─────────────┐            ┌─────────────┐
│ Random       │            │ Optimized    │
│ Strategies   │──evolve──▶│ Strategies   │
│ (100 pop)    │            │              │
└──────┬──────┘            └──────────────┘
       │
       ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Evaluate    │──▶ │  Select      │──▶ │  Crossover   │
│  Fitness     │    │  (Tournament)│    │  + Mutate    │
│  vs Attacks  │    │  Top 10%     │    │  Rate: 10%   │
└──────────────┘    └──────────────┘    └──────────────┘
```

Each strategy is a set of defensive rules (3-8 rules per strategy).
Rule types include: IP blocking, rate limiting, geo-blocking, port restriction,
payload inspection, protocol whitelisting, time-based access, behavioral locks,
honeypot redirection, and adaptive authentication.

## 6. Microservices Decomposition (Production)

For production deployment, each engine becomes an independent microservice:

| Service | Port | Scaling | State |
|---------|------|---------|-------|
| ingestion-svc | 8001 | Horizontal (Kafka consumers) | Stateless |
| baseline-svc | 8002 | Per-entity sharding | Redis |
| prediction-svc | 8003 | GPU-backed replicas | Model store |
| intent-svc | 8004 | GPU-backed replicas | Model store |
| orchestrator-svc | 8005 | Active-passive | PostgreSQL |
| honeynet-svc | 8006 | Dynamic scaling | Container registry |
| deception-svc | 8007 | Single instance | In-memory |
| attacker-intel-svc | 8008 | Single instance | Elasticsearch |
| defense-svc | 8009 | Active-passive | Firewall APIs |
| evolution-svc | 8010 | Single instance | PostgreSQL |
| genetic-svc | 8011 | Compute-intensive | In-memory |
| red-team-svc | 8012 | Isolated network | Sandboxed |
| digital-twin-svc | 8013 | Compute-intensive | In-memory |
| mtd-svc | 8014 | Active-passive | Network APIs |
| distributed-svc | 8015 | Peer-to-peer | Gossip protocol |
| identity-svc | 8016 | Horizontal | Redis |
| time-prediction-svc | 8017 | Single instance | TimescaleDB |
| threat-intel-svc | 8018 | Horizontal | Elasticsearch |
| api-gateway | 8000 | Horizontal | Stateless |
| dashboard | 3000 | CDN-backed | Static |
