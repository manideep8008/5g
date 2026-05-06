# Privacy-Preserving UE Behavioural Summary Exchange for Adaptive Access Tiering Across Private 5G Domains

**Simplified Workshop Paper Implementation Plan**

Target deadline: 12 August 2026
Stack: OAI CN5G + USRP B210 + FastAPI + Redis + Postgres + LLM (hybrid policy)
Scope: Feasibility prototype — 1 real UE, auto-generated oracle, 6-week build

---

## 1. What this project does

Two private 5G networks. Network A is real (OAI CN5G + USRP B210). Network B is simulated.

When a UE that has history on Network A tries to access Network B, Network B requests a **privacy-preserving behavioural summary** from Network A. The summary contains only bucketed categorical labels (e.g., `auth_stability: "high"`, `traffic_pattern: "volatile"`) — no raw data, no IMSI, no byte counts, no logs.

Network B feeds this summary into a **hybrid policy engine**: an LLM proposes an access tier with reasoning, then a deterministic safety floor clips the decision if the LLM is too permissive. The result is one of four tiers:

| Tier | Meaning |
|------|---------|
| T0_REJECT | Block access entirely |
| T1_RESTRICTED_ACCESS | Allow with bandwidth caps and service restrictions |
| T2_MONITORED_ACCESS | Allow with active monitoring and re-evaluation |
| T3_FULL_ACCESS | Allow normally |

**Key design invariants:**
- No raw data crosses the network boundary. Summary schema is allowlist-enforced server-side.
- Identity is pseudonymous: IMSI → `UE_HASH_*` via HMAC-SHA256.
- The LLM can tighten but never loosen the deterministic tier. This is the defense against prompt injection.
- Every summary disclosed is audit-logged in Postgres.

---

## 2. What we are building for this workshop

### In scope (the 3 pillars)

**Pillar 1 — Real OAI 5G integration.**
One real UE (IMSI 208950000000031) on a USRP B210. AMF log parser extracts registration, authentication, PDU session, and context release events. UPF Prometheus scraper collects traffic metrics. This proves the system works on real, unmodified OAI CN5G infrastructure — not just simulation.

**Pillar 2 — Privacy-preserving summary schema.**
All numeric features (auth failure rates, throughput, spike counts) are bucketed into categorical labels before leaving Network A. The Pydantic schema rejects any field outside the allowlist. Summaries are not fingerprintable because bucketization collapses many UEs into identical summary tuples.

**Pillar 3 — Hybrid LLM + safety floor policy engine.**
The LLM provides natural-language reasoning for access decisions. The deterministic safety floor provides a hard upper bound on permissiveness. Together they outperform either component alone: the LLM handles ambiguous cases better than rules, and the safety floor catches prompt injection that would fool the LLM.

### Out of scope (documented as future work)

- Multi-SIM data collection campaigns (5-10 SIMs, 200-500 sessions)
- Mid-session re-evaluation with anomaly-driven triggers
- Privacy fingerprinting / re-identification analysis
- Cross-operator UE identity federation / SUPI handover
- Real 5G roaming signalling
- Inter-rater agreement (Cohen's kappa) on oracle labeling
- Differential privacy or k-anonymity guarantees
- Multi-tenant operation
- Production hardening (mTLS, rate limiting, HA deployment)

---

## 3. System architecture (simplified)

```
┌────────────────────────────────────────────┐    ┌────────────────────────────────────────┐
│           NETWORK A (real)                 │    │     NETWORK B (simulated process)      │
│                                            │    │                                        │
│  Real UE → USRP B210 → OAI gNB → OAI 5GC │    │  Experiment runner injects             │
│                          (AMF/SMF/UPF)     │    │  UE_ACCESS_REQUEST event               │
│                              │             │    │         │                              │
│                              ▼             │    │         ▼                              │
│  ┌──────────────────────────────────┐      │    │  ┌──────────────────────────────┐      │
│  │ Behaviour Collector              │      │    │  │ Network B FastAPI            │      │
│  │  • AMF log parser               │      │    │  │  POST /v1/access/request     │      │
│  │  • UPF Prometheus scraper       │      │    │  └──────────┬───────────────────┘      │
│  └──────────────┬───────────────────┘      │    │             │                          │
│                 ▼                          │    │             ▼                          │
│  ┌──────────────────────────────────┐      │    │  ┌──────────────────────────────┐      │
│  │ Postgres + Redis                │      │    │  │ Hybrid Policy Engine         │      │
│  │  (sessions, identity, flags)    │      │    │  │  1. Deterministic risk score  │      │
│  └──────────────┬───────────────────┘      │    │  │  2. LLM structured output    │      │
│                 ▼                          │    │  │  3. Safety floor clip         │      │
│  ┌──────────────────────────────────┐      │    │  └──────────────────────────────┘      │
│  │ Summary Generator               │      │    │             │                          │
│  │  • Bucketization                │      │    │             ▼                          │
│  │  • Allowlist projection         │      │    │  ┌──────────────────────────────┐      │
│  │  • HMAC pseudonymisation        │      │    │  │ Decision Logger              │      │
│  └──────────────┬───────────────────┘      │    │  │  tier, reason, audit trail   │      │
│                 ▼                          │    │  └──────────────────────────────┘      │
│  ┌──────────────────────────────────┐      │    │                                        │
│  │ Network A FastAPI               │◄─────┼────┼────────────────────────────────────────│
│  │  POST /v1/summary/request       │      │    │                                        │
│  └──────────────────────────────────┘      │    │                                        │
└────────────────────────────────────────────┘    └────────────────────────────────────────┘
```

---

## 4. Project structure

```
IBN-ZTA-implementaion/
├── IMPLEMENTATION_PLAN.md          # this file
├── docker-compose.yml              # Postgres + Redis + both FastAPIs
├── schema.sql                      # Postgres tables
├── .env.example                    # secrets template (never commit .env)
│
├── network_a/
│   ├── collector/
│   │   ├── amf_log_parser.py       # parse OAI AMF "manual" log format
│   │   ├── upf_traffic_collector.py # Prometheus scraper for UPF metrics
│   │   ├── feature_extractor.py    # join AMF events + UPF metrics → session records
│   │   └── collector_main.py       # long-running: tail logs, scrape, write DB
│   ├── identity/
│   │   ├── ue_hasher.py            # HMAC-SHA256 pseudonymisation
│   │   └── identity_mapper.py      # Postgres-backed IMSI ↔ pseudonym map
│   ├── summary/
│   │   ├── summary_schema.py       # Pydantic allowlist (single source of truth)
│   │   ├── profile_builder.py      # aggregate sessions per UE from Postgres
│   │   ├── risk_flag_generator.py  # apply thresholds → bucketed labels
│   │   └── summary_generator.py    # produce SummaryResponse, enforce allowlist
│   └── api/
│       ├── app.py                  # FastAPI app (port 8001)
│       └── routes.py               # POST /v1/summary/request, GET /v1/health
│
├── network_b/
│   ├── policy/
│   │   ├── policy_engine.py        # hybrid LLM + safety floor
│   │   ├── risk_score.py           # deterministic risk in [0,1]
│   │   └── tier_mapper.py          # risk → max tier rules
│   ├── decision/
│   │   ├── decision_service.py     # orchestrate: fetch summary → policy → log
│   │   └── decision_logger.py      # write decisions to data/access_decisions/
│   └── api/
│       ├── app.py                  # FastAPI app (port 8002)
│       └── routes.py               # POST /v1/access/request, GET /v1/health
│
├── experiments/
│   ├── oracle_dataset.json         # auto-generated + hand-labeled scenarios
│   ├── generate_oracle.py          # script to auto-generate oracle from bucket space
│   ├── run_real_ue_demo.py         # end-to-end demo with real UE
│   ├── run_scenario_experiments.py # run all systems on oracle dataset
│   └── generate_results.py         # produce tables + figures for paper
│
├── baselines/
│   ├── rule_without_summary.py     # rules + access request only (no summary)
│   └── single_llm_decision.py      # LLM + access request only (no summary)
│
├── tests/
│   ├── test_amf_parser.py
│   ├── test_summary_schema.py
│   ├── test_policy_engine.py
│   ├── test_upf_collector.py
│   └── test_prompt_injection.py    # 5 adversarial scenarios
│
├── data/
│   ├── logs/                       # archived OAI log samples
│   ├── summaries/                  # generated summaries
│   ├── access_decisions/           # decision JSONs
│   └── results/                    # evaluation results + figures
│
├── config/
│   ├── network_a_config.yaml       # bucketization thresholds, scrape intervals
│   └── network_b_policy.yaml       # risk weights, LLM model config
│
└── scripts/
    ├── run_demo.sh                 # one-command end-to-end demo
    └── run_evaluation.sh           # one-command full evaluation
```

---

## 5. Evaluation design (simplified)

### Oracle dataset: ~75 scenarios (auto-generated + hand-labeled)

Instead of manually labeling 80-150 scenarios, we:

1. **Auto-generate ~55 unambiguous scenarios** from the bucket space.
   The `generate_oracle.py` script enumerates valid summary combinations, computes `deterministic_risk_score()` and `risk_to_max_tier()`, and labels scenarios where all fields agree on severity. These are the "easy" cases — all-good → T3, all-bad → T0.

2. **Hand-label ~15 conflicting-signal scenarios.** Cases where summary fields disagree (e.g., high auth stability but recent anomaly). These are where the LLM's reasoning should outperform pure rules.

3. **Add 5 prompt-injection scenarios.** Adversarial summaries that attempt to manipulate the LLM into granting T3. The safety floor should catch all of them.

**Tier distribution target:** ~30% T3, ~30% T2, ~25% T1, ~15% T0.

### 3 experimental conditions (not 4)

| System | What it tests |
|--------|---------------|
| `full` (ours) | Summary + LLM + safety floor |
| `rule_without_summary` | Rules + access request only, no summary from Network A |
| `single_llm` | LLM + access request only, no summary from Network A |

**Dropped:** `rule_with_summary` baseline. It answers "is the LLM worth it over rules?" — interesting but not essential for the core contribution. Mention as future comparison.

### Evaluation runs

75 scenarios × 3 systems × 3 seeds = **675 runs total**
- Local LLM (Llama-3.1-8B via Ollama): ~15 minutes
- Cloud LLM (Claude Sonnet): ~12 minutes at 1s/call

### Metrics to report

**Decision quality:**
- Tier accuracy vs. oracle (overall + per-tier)
- 4×4 confusion matrix per system
- Severity-weighted error (T3-when-oracle-is-T0 penalized heavily)

**Latency:**
- P50/P95 end-to-end (runner request → decision)
- Breakdown: summary fetch, LLM call, safety floor

**Robustness:**
- Prompt-injection success rate: without safety floor vs. with safety floor
- Target: safety floor reduces injection success to ~0%

**Privacy (lightweight):**
- Bytes disclosed per summary request (deterministic upper bound)
- Audit-log completeness: every disclosure has a `summary_disclosure` row

---

## 6. Build order (6 weeks)

### Week 1 — Vertical slice
Get one hardcoded end-to-end happy path working:
1. Real UE registers to OAI Network A
2. AMF parser detects registration + first PDU session
3. Collector writes one row to Postgres `ue_session`
4. Pseudonym allocated: IMSI 208950000000031 → UE_HASH_001
5. Network A FastAPI returns a **hardcoded** "high stability" summary
6. Runner posts access request to Network B FastAPI
7. Network B calls Network A, gets summary
8. Policy engine uses a **3-line rule** (skip LLM). Returns T3 for "high stability"
9. Decision written to `data/access_decisions/`

**End state:** `./scripts/run_demo.sh` produces one valid Decision JSON.

### Week 2 — Real parsers + database + identity
- Wire AMF parser against actual log format
- Implement UPF Prometheus scraper (verify metrics with `curl :9090/metrics`)
- Deploy Postgres schema (`schema.sql`)
- HMAC pseudonymisation with unit tests
- Feature extractor: join AMF events + UPF snapshots → session records

**End state:** Collector running as a service. Real session rows accumulating.

### Week 3 — Summary generator + both APIs
- Profile builder: aggregate sessions per UE from Postgres
- Risk flag generator: apply bucket thresholds
- Summary generator: produce `SummaryResponse`, enforce allowlist
- Network A API: `POST /v1/summary/request` returns real (non-hardcoded) summary
- Network B API: `POST /v1/access/request` returns decisions
- Use rule-based policy (no LLM yet)

**End state:** `curl` POST returns a real bucketed summary. End-to-end decisions on real UE data.

### Week 4 — LLM integration + safety floor + baselines
- Integrate Ollama (Llama-3.1-8B-Instruct, JSON mode, temperature=0)
- Structured output via function calling / JSON schema
- Safety floor clipping in tier_mapper.py
- Log LLM proposal separately from final tier
- Implement 2 baselines: `rule_without_summary`, `single_llm`
- 5 prompt-injection test cases

**End state:** Hybrid decisions working. Prompt-injection tests failing safely (safety floor clips).

### Week 5 — Oracle + evaluation
- Run `generate_oracle.py` to auto-generate unambiguous scenarios
- Hand-label ~15 conflicting-signal scenarios (30 min)
- Add 5 adversarial scenarios
- Run `run_scenario_experiments.py` across all 3 systems
- Run `generate_results.py` to produce confusion matrices + tables
- Optional: one run with Claude Sonnet as upper-bound check

**End state:** Complete evaluation results. All paper tables/figures ready.

### Week 6 — Demo + paper
- Clean up `run_real_ue_demo.py` — runnable, recorded
- Record terminal demo (asciinema or screen recording)
- Write paper draft
- Ship `make reproduce` that regenerates everything from archived logs

**End state:** Submittable paper + reproducible artifact.

---

## 7. LLM configuration

**Primary model:** Llama-3.1-8B-Instruct via Ollama
- JSON mode, temperature=0
- Reproducible, free, runs locally
- Pin exact model version in `config/network_b_policy.yaml`

**Upper-bound check (optional):** Claude Sonnet via API
- Structured output, temperature=0
- Run once, report the delta as "frontier-model headroom"
- Shows reviewers you didn't pick a weak model and call it a day

Log model + version + temperature + prompt + response for every call.

---

## 8. Claims we CAN defend

- "A privacy-preserving behavioural summary, generated from real OAI 5G core state, is sufficient for an LLM-based policy engine to produce access-tier decisions consistent with ground truth for N% of evaluated scenarios."
- "A deterministic safety floor reduces prompt-injection-induced tier inflation from X% to ~0%."
- "Schema-enforced bucketization produces summaries with a bounded disclosure size of N bytes per request."
- "Real OAI integration: the system operates against unmodified OAI CN5G AMF and UPF using log tailing and Prometheus scraping."

## 9. Claims we CANNOT make

- Differential privacy or k-anonymity guarantees
- Cross-operator UE identity federation
- Real 5G roaming / SUPI handover
- Network B discovers the UE (the runner does)
- Sub-millisecond decisions (LLM latency)
- Multi-tenant or multi-UE concurrent operation
- Production-ready deployment

## 10. Limitations to state explicitly

- Single USRP B210, single real Network A, no real Network B radio
- Single UE for real integration; evaluation uses systematically generated scenarios
- LLM decisions are non-deterministic (provider model updates, infrastructure variability)
- Oracle is auto-generated for unambiguous cases + expert-labeled for ambiguous cases
- Bucketization granularity is fixed; learned bucketizations are future work
- Pseudonym federation is assumed, not implemented
- Mid-session re-evaluation is designed but not implemented

---

## 11. Postgres schema

```sql
CREATE TABLE ue_identity (
    pseudonym       VARCHAR(32) PRIMARY KEY,
    imsi_hmac       VARCHAR(64) NOT NULL UNIQUE,
    first_seen      TIMESTAMPTZ NOT NULL,
    network_b_id    VARCHAR(64) NOT NULL,
    notes           TEXT
);

CREATE TABLE ue_session (
    session_id           BIGSERIAL PRIMARY KEY,
    pseudonym            VARCHAR(32) REFERENCES ue_identity(pseudonym),
    started_at           TIMESTAMPTZ NOT NULL,
    ended_at             TIMESTAMPTZ,
    duration_sec         INTEGER,
    registration_success BOOLEAN NOT NULL,
    auth_attempts        INTEGER NOT NULL DEFAULT 0,
    auth_failures        INTEGER NOT NULL DEFAULT 0,
    pdu_attempts         INTEGER NOT NULL DEFAULT 0,
    pdu_failures         INTEGER NOT NULL DEFAULT 0,
    requested_slice      VARCHAR(16),
    requested_dnn        VARCHAR(64),
    bytes_uplink         BIGINT NOT NULL DEFAULT 0,
    bytes_downlink       BIGINT NOT NULL DEFAULT 0,
    peak_throughput_kbps INTEGER,
    spike_count          INTEGER NOT NULL DEFAULT 0,
    cell_id              VARCHAR(16),
    raw_log_pointer      VARCHAR(256)
);

CREATE INDEX ix_ue_session_pseudonym_time ON ue_session(pseudonym, started_at DESC);

CREATE TABLE ue_risk_flag (
    flag_id        BIGSERIAL PRIMARY KEY,
    pseudonym      VARCHAR(32) REFERENCES ue_identity(pseudonym),
    flagged_at     TIMESTAMPTZ NOT NULL,
    flag_type      VARCHAR(32),
    severity       VARCHAR(16),
    evidence       JSONB,
    cleared_at     TIMESTAMPTZ
);

CREATE TABLE summary_disclosure (
    disclosure_id    BIGSERIAL PRIMARY KEY,
    request_id       VARCHAR(64) NOT NULL,
    pseudonym        VARCHAR(32) NOT NULL,
    network_b_id     VARCHAR(64) NOT NULL,
    disclosed_at     TIMESTAMPTZ NOT NULL,
    summary_payload  JSONB NOT NULL,
    requested_fields TEXT[]
);
```

---

## 12. JSON message formats

### SummaryRequest (Network B → Network A)

```json
{
  "request_id": "REQ-001",
  "ue_pseudonym": "UE_HASH_001",
  "requested_fields": ["auth_stability", "pdu_session_stability",
                       "traffic_pattern", "slice_usage",
                       "recent_anomalies", "behaviour_label"],
  "network_b_context": {
    "requested_slice": "eMBB",
    "requested_dnn": "internet",
    "requested_service": "standard_data"
  }
}
```

### SummaryResponse (Network A → Network B)

```json
{
  "request_id": "REQ-001",
  "ue_pseudonym": "UE_HASH_001",
  "summary": {
    "auth_stability": "high",
    "pdu_session_stability": "high",
    "traffic_pattern": "stable",
    "known_slice_usage": ["eMBB"],
    "recent_anomaly": false,
    "behaviour_label": "normal"
  },
  "network_a_recommendation": "T3_FULL_ACCESS",
  "confidence": 0.92,
  "privacy_level": "summary_only",
  "issued_at": "2026-04-15T12:34:56Z",
  "summary_window_sec": 86400
}
```

### AccessRequest (runner → Network B)

```json
{
  "event_type": "UE_ACCESS_REQUEST_AT_NETWORK_B",
  "request_id": "REQ-001",
  "ue_pseudonym": "UE_HASH_001",
  "requested_network": "Network_B",
  "requested_slice": "eMBB",
  "requested_dnn": "internet",
  "requested_service": "standard_data",
  "timestamp": "2026-04-15T12:34:56Z"
}
```

### Decision (Network B → runner)

```json
{
  "request_id": "REQ-001",
  "ue_pseudonym": "UE_HASH_001",
  "final_tier": "T2_MONITORED_ACCESS",
  "risk_score": 0.38,
  "reason": "Recent anomaly flag warrants monitoring despite stable auth.",
  "policy_engine_metadata": {
    "llm_model_id": "llama-3.1-8b-instruct",
    "llm_temperature": 0.0,
    "llm_proposed_tier": "T3_FULL_ACCESS",
    "safety_floor_clipped": true,
    "safety_floor_reason": "recent_anomaly=true forced clip from T3 to T2",
    "deterministic_max_tier": "T2_MONITORED_ACCESS"
  },
  "simulated_enforcement": {
    "bandwidth_cap_mbps": 50,
    "monitoring_interval_sec": 60,
    "allowed_services": ["standard_data"]
  },
  "decided_at": "2026-04-15T12:34:57Z"
}
```

---

*This is the working spec for the simplified prototype. Deviations should be deliberate and documented.*
