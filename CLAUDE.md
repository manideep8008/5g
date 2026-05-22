# IBN-ZTA: Privacy-Preserving Adaptive Access Tiering for 5G

## What This Is

A research prototype where two private 5G networks exchange **privacy-preserving behavioural summaries** (bucketed categorical labels only) to make adaptive Zero Trust access decisions. Network A (real OAI CN5G core) collects UE behaviour and generates summaries. Network B (simulated) runs a hybrid LLM + deterministic safety floor policy engine that decides one of four access tiers (T0-T3).

## Architecture

```
Network A (port 8001)                    Network B (port 8002)
────────────────────                     ────────────────────
AMF logs ──► Collector                   Access request arrives
UPF metrics ──► │                                │
                v                                v
         Feature Extractor               fetch_summary() from Net A
                │                                │
                v                                v
         Profile Builder                 risk_score.py (deterministic)
                │                                │
                v                                v
         Bucketize → Summary             llm_client.py (Ollama, optional)
                │                                │
                v                                v
         API returns summary ◄───────── tier_mapper.py + safety floor
                                                 │
                                                 v
                                         AccessDecision (JSON logged)
```

## Directory Structure

```
network_a/
  collector/          AMF log parser, UPF Prometheus scraper, feature extractor
  identity/           HMAC-SHA256 pseudonymisation (IMSI → UE_HASH_*)
  summary/            Profile builder, risk flag generator, summary schema (Pydantic)
  api/                FastAPI on :8001 — POST /v1/summary/request
  db.py               Async Postgres pool with in-memory fallback

network_b/
  policy/             risk_score.py, tier_mapper.py (safety floor), llm_client.py, policy_engine.py
  decision/           decision_service.py (orchestrator), decision_logger.py
  api/                FastAPI on :8002 — POST /v1/access/request

baselines/            rule_without_summary.py, single_llm_decision.py
experiments/          generate_oracle.py, run_scenario_experiments.py, generate_results.py
tests/                15 test files, 175 tests
config/               network_a_config.yaml (bucketization), network_b_policy.yaml (policy)
scripts/              start_with_oai.sh, run_demo.sh, run_evaluation.sh, reproduce.sh
data/                 logs, access decisions, experiment results, oracle dataset
```

## Key Data Flow

1. `collector_main.py` tails AMF Docker logs + scrapes UPF Prometheus every 10s
2. `amf_log_parser.py` regex-parses 14 event types (registration, auth, PDU, context release)
3. `feature_extractor.py` groups events by IMSI, waits for CONTEXT_RELEASE, builds SessionRecord
4. `ue_hasher.py` pseudonymises IMSI via HMAC-SHA256
5. Sessions stored in Postgres (`ue_session`, `ue_identity`, `ue_risk_flag` tables)
6. On summary request: `profile_builder.py` aggregates last 200 sessions into UeProfile
7. `risk_flag_generator.py` bucketizes profile into categorical labels (HIGH/MEDIUM/LOW, STABLE/VOLATILE, NORMAL/ANOMALOUS)
8. Network B receives summary, `risk_score.py` computes weighted score [0,1]
9. `tier_mapper.py` maps score to tier, then safety floor clips LLM proposal downward if needed
10. `decision_logger.py` writes full decision to JSON in `data/access_decisions/`

## Key Invariants

- **No raw data crosses the boundary** — only 6 bucketed label fields, allowlist-enforced
- **IMSI never shared** — only `UE_HASH_<12hex>` pseudonym
- **LLM can tighten, never loosen** — safety floor hard-clips (recent_anomaly=true → max T2, auth_stability=LOW → max T1)
- **Deterministic fallback** — if LLM unavailable, rules-only engine applies
- **Conservative default** — if Network A unreachable → T1_RESTRICTED_ACCESS

## How to Run

```bash
# Prerequisites: OAI CN5G core running, gNB connected, SIM programmed, UE attached

# 1. Setup
cp .env.example .env              # Edit: set HMAC_SECRET_KEY, LLM endpoint
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
docker compose up -d              # Postgres + Redis

# 2. Start all services
./scripts/start_with_oai.sh       # Collector + Network A API + Network B API

# 3. Run tests
pytest tests/ -v

# 4. Run evaluation
python3 -m experiments.generate_oracle
./scripts/run_evaluation.sh
python3 -m experiments.generate_results
```

## Config Files

- `config/network_a_config.yaml` — bucketization thresholds (auth failure rate <5% = HIGH stability, etc.)
- `config/network_b_policy.yaml` — policy mode (hybrid/rules_only), risk weights, tier thresholds, safety floor rules, LLM model config
- `.env` — Postgres, Redis, HMAC key, OAI integration, LLM endpoint

## Tech Stack

- Python 3.13+, FastAPI, Pydantic, asyncpg, httpx
- Postgres 16 (async), Redis 7
- Ollama (local LLM) or cloud-hosted
- OAI CN5G v2.2.1, OAI gNB + USRP B210
- Docker Compose (Postgres/Redis join OAI's `oai-cn5g-public-net` network)

## API Endpoints

- `GET  :8001/v1/health` — Network A health check
- `POST :8001/v1/summary/request` — returns `SummaryResponse` (behavioural summary)
- `GET  :8002/v1/health` — Network B health check
- `POST :8002/v1/access/request` — returns `AccessDecision` (tier + reasoning)

## Testing

175 tests across 15 files. Key test categories:
- Unit: parser, hasher, risk score, tier mapper, profile builder
- Integration: summary generator, policy engine, decision service
- Security: prompt injection resistance (5 adversarial scenarios)
- Baselines: rule_without_summary accuracy, single_llm without safety floor

## Conventions

- All Pydantic models in `summary_schema.py` (shared between networks)
- Enums: `Tier`, `AuthStability`, `PduSessionStability`, `TrafficPattern`, `BehaviourLabel`
- Config loaded via PyYAML, env vars via python-dotenv
- Async everywhere (asyncpg, httpx)
- In-memory fallback when Postgres/Prometheus unavailable
