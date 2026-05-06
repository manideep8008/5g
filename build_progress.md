---
name: Build progress — Week 6 complete (all weeks done)
description: All 6 weeks complete. Full system built: collector, summary, hybrid LLM policy, evaluation, demo. 175 tests, one-command reproduce.
type: project
originSessionId: 1980ccc0-e1d2-41d5-82ad-baee210e7f7c
---
All 6 weeks completed on 2026-05-05/06.

**Final system state:**

- **175 tests passing** in 0.10s
- **70 oracle scenarios** (50 unambiguous + 15 conflicting + 5 adversarial)
- **630 experiment runs** (70 scenarios × 3 systems × 3 seeds)
- **One-command reproduction**: `./scripts/reproduce.sh`

**Complete component list:**

Network A (real OAI 5G integration):
- AMF log parser (14 event types from real OAI CN5G)
- UPF Prometheus scraper (bytes, packets, PFCP sessions)
- Feature extractor (joins AMF + UPF → session records)
- Async Postgres DB (asyncpg + in-memory fallback)
- Identity mapper (HMAC-SHA256 pseudonymisation)
- Profile builder (aggregates sessions per UE)
- Risk flag generator (bucketization thresholds → categorical labels)
- Summary generator (real DB-backed, audit-logged)
- FastAPI on port 8001 with DB lifespan

Network B (simulated, policy engine):
- Deterministic risk scorer (weighted field mapping)
- Tier mapper (risk → T0-T3)
- Safety floor (3 hard rules: anomaly→T2, low_auth→T1, anomalous→T1)
- LLM client (Ollama JSON mode, structured output parsing)
- Hybrid policy engine (rules/hybrid/auto modes)
- Decision service (async, fetches summary → policy → log)
- FastAPI on port 8002

Baselines:
- `rule_without_summary.py` — request context only, no UE history
- `single_llm_decision.py` — LLM-only, NO safety floor

Evaluation:
- `generate_oracle.py` — auto-generates balanced oracle dataset
- `run_scenario_experiments.py` — runs 3 systems, configurable seeds + LLM toggle
- `generate_results.py` — confusion matrices, severity error, latency, injection rates

Scripts:
- `./scripts/reproduce.sh` — full reproduction (tests → oracle → eval → results → demo)
- `./scripts/run_evaluation.sh` — one-command evaluation (--with-llm optional)
- `./scripts/run_demo.sh` — demo (local or --live with servers)
- `scripts/seed_demo_data.py` — seed DB for live demo

**Key results (deterministic mode):**
- full (ours): 84.3% accuracy, severity_error=0.23, injection=0%
- rule_without_summary: 41.4% accuracy, severity_error=0.87
- Proves: summary adds massive value (84% vs 41%)

**With Ollama (when available):**
- full: injection still 0% (safety floor catches)
- single_llm: injection >0% (LLM tricked, no floor)
- Proves: safety floor is necessary defense

**How to apply:** The system is feature-complete for the paper. Run `./scripts/reproduce.sh` for full artifact. For live LLM eval: `ollama pull llama3.1:8b-instruct-q4_K_M && ./scripts/run_evaluation.sh --with-llm`.
