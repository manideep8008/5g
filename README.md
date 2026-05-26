# Privacy-Preserving UE Behavioural Summary Exchange for Adaptive Access Tiering Across Private 5G Domains

When a UE (phone/device) with history on one private 5G network tries to join a second network, the second network asks the first: "is this UE trustworthy?" The first network responds with a **privacy-preserving behavioural summary** — bucketed categorical labels only, no raw data.

The second network feeds this summary into a **hybrid LLM + safety floor policy engine** that decides one of four access tiers:

| Tier | Meaning |
|------|---------|
| T0_REJECT | Block access |
| T1_RESTRICTED_ACCESS | Bandwidth caps, service restrictions |
| T2_MONITORED_ACCESS | Active monitoring, re-evaluation |
| T3_FULL_ACCESS | Normal access |

## Architecture

```
┌─── Network A (real OAI 5G core) ──────┐    ┌─── Network B (simulated) ─────────┐
│                                        │    │                                    │
│  UE → gNB → AMF/SMF/UPF               │    │  Access request arrives            │
│              │                         │    │         │                          │
│              v                         │    │         v                          │
│  Behaviour Collector                   │    │  Hybrid Policy Engine              │
│   • AMF log parser (14 event types,    │    │   1. Deterministic risk score      │
│     real OAI CN5G v2.2.1 format)       │    │   2. RAG retrieves policy context  │
│   • UPF Prometheus scraper (traffic)   │    │   3. LLM proposes tier + reasoning │
│              │                         │    │   4. Safety floor clips if needed  │
│              │                         │    │         │                          │
│              v                         │    │         v                          │
│  Summary Generator                     │    │  Decision: tier + audit trail      │
│   • Bucketize raw data → labels        │    │                                    │
│   • HMAC pseudonymise IMSI             │    │                                    │
│   • Allowlist-enforce schema           │    │                                    │
│              │                         │    │                                    │
│              v                         │    │                                    │
│  Network A API ◄───────────────────────┼────┼── Network B fetches summary        │
│  POST /v1/summary/request              │    │                                    │
└────────────────────────────────────────┘    └────────────────────────────────────┘
```

## Key Design Invariants

- **No raw data crosses the network boundary.** Summaries contain only bucketed labels (`auth_stability: "high"`, `traffic_pattern: "volatile"`). Schema is allowlist-enforced server-side.
- **Identity is pseudonymous.** IMSI is never shared — only `UE_HASH_*` via HMAC-SHA256.
- **LLM can tighten but never loosen.** The deterministic safety floor provides a hard upper bound on permissiveness, defending against prompt injection.
- **LLM decisions are grounded.** A RAG layer retrieves the most relevant policy snippets from a local knowledge base and supplies them to the LLM as context, so reasoning cites concrete policy rather than free-form guesses.
- **Storage degrades gracefully.** Network A speaks to a `StorageBackend` Protocol with two interchangeable implementations — `PostgresStorage` (production) and `InMemoryStorage` (dev without Docker). Same contract, no branching at call sites.
- **Every disclosure is audit-logged** in Postgres.

## Project Structure

```
IBN-ZTA-implementaion/           # This repo — research code only
├── docker-compose.yml           # Postgres + Redis (joins core's network)
├── schema.sql                   # Postgres tables
├── .env.example                 # Configuration template
├── network_a/
│   ├── collector/               # AMF log parser, UPF scraper, feature extractor
│   ├── identity/                # HMAC pseudonymisation
│   ├── summary/                 # Bucketization, allowlist, summary generator
│   └── api/                     # FastAPI on :8001
├── network_b/
│   ├── collector/               # Attachment watcher (triggers access requests)
│   ├── policy/                  # Hybrid policy engine, LLM client, safety floor
│   ├── rag/                     # Knowledge base, embeddings, retriever, vector store
│   ├── decision/                # Decision service, audit logger
│   └── api/                     # FastAPI on :8002
├── experiments/                 # Oracle dataset, evaluation runner, results
├── baselines/                   # rule_without_summary, single_llm_decision
├── tests/                       # 223 tests
├── config/                      # Bucketization thresholds, LLM config, RAG policies
└── scripts/
    ├── start_with_oai.sh        # Start collector + both APIs
    ├── build_knowledge_base.py  # Build RAG vector store from policy docs
    ├── run_demo.sh              # End-to-end demo
    └── run_evaluation.sh        # Full evaluation run
```

The OAI 5G core, gNB, and pySIM live in separate folders:

```
oai-cn5g/                        # 5G core — own docker-compose, creates network
oai-gnb/                         # gNB — connects to AMF
pysim/                           # SIM programmer
IBN-ZTA-implementaion/           # This repo
```

## Prerequisites

- Linux system (for OAI 5G core + gNB)
- Docker + Docker Compose
- Python 3.13+
- OAI CN5G core running (separate `oai-cn5g/` folder)
- gNB connected to core
- Programmed SIM + UE attached

## Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/manideep8008/5g.git IBN-ZTA-implementaion
cd IBN-ZTA-implementaion
cp .env.example .env
# Edit .env — set HMAC_SECRET_KEY, LLM endpoint, etc.

# 2. Start the OAI 5G core (separate folder)
cd ../oai-cn5g
docker compose up -d

# 3. Start gNB, program SIM, attach UE (your setup)

# 4. Start IBN-ZTA infrastructure
cd ../IBN-ZTA-implementaion
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
docker compose up -d              # Postgres + Redis

# 5. Build the RAG knowledge base (one-time, ~10s)
python3 scripts/build_knowledge_base.py

# 6. Start collector + APIs
./scripts/start_with_oai.sh

# Alternative: run without Postgres (in-memory fallback)
# Skip step 4's docker compose — the API auto-detects the missing DB
# and embeds the collector in the same process.
./scripts/start_with_oai.sh
```

This starts:
- **AMF log capture** — pipes `docker logs oai-amf` to a file
- **Behaviour Collector** — tails AMF log + scrapes UPF Prometheus at `:9090`. When Postgres is unavailable, the collector runs embedded inside the Network A API process so both share the same in-memory store.
- **Network A API** on `:8001` — serves behavioural summaries
- **Network B API** on `:8002` — makes access tier decisions

## Demo: Seed Scenarios

If you don't have a real UE attached (or want repeatable demo data), seed three simulated UE profiles that trigger different classification tiers:

```bash
curl -X POST http://localhost:8001/admin/seed-scenarios | python3 -m json.tool
```

This creates:

| Pseudonym | Profile | Expected Tier |
|-----------|---------|---------------|
| `UE_SIM_NORMAL` | Clean — zero failures, stable traffic | T3_FULL_ACCESS |
| `UE_SIM_SUSPICIOUS` | Moderate auth failures + traffic spikes | T2_MONITORED_ACCESS |
| `UE_SIM_ANOMALOUS` | High failure rates + active risk flags | T0_REJECT |

Then request a summary and access decision:

```bash
# Get behavioural summary from Network A
curl -X POST http://localhost:8001/v1/summary/request \
  -H "Content-Type: application/json" \
  -d '{"ue_pseudonym": "UE_SIM_SUSPICIOUS", "requesting_network": "Network_B"}'

# Get access tier decision from Network B
curl -X POST http://localhost:8002/v1/access/request \
  -H "Content-Type: application/json" \
  -d '{"ue_pseudonym": "UE_SIM_SUSPICIOUS", "requesting_network": "Network_B"}'
```

## Testing

```bash
pytest tests/ -v          # Run all 223 tests
pytest tests/ -q          # Quick summary
```

## Evaluation

```bash
# Generate oracle dataset
python3 -m experiments.generate_oracle

# Run all 3 systems against oracle (75 scenarios x 3 systems x 3 seeds)
./scripts/run_evaluation.sh

# Generate tables and figures for paper
python3 -m experiments.generate_results
```

## API Endpoints

### Network A (Summary Provider) — `:8001`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/summary/request` | Returns privacy-preserving behavioural summary |
| POST | `/admin/seed-scenarios` | Seeds 3 simulated UEs (normal/suspicious/anomalous) for demo |
| GET | `/v1/health` | Health check |

### Network B (Policy Engine) — `:8002`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/access/request` | Returns access tier decision |
| GET | `/v1/health` | Health check |

## Stack

- **5G Core**: OAI CN5G v2.2.1 (AMF, SMF, UPF, NRF, UDR, UDM, AUSF)
- **Radio**: OAI gNB + USRP B210
- **Backend**: FastAPI, Postgres 16, Redis 7
- **LLM**: Ollama (local) or cloud-hosted
- **Language**: Python 3.13+

## License

Research prototype — not for production use.
