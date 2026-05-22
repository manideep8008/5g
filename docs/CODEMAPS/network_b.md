# Network B — Policy Engine & Decision Service

## Overview

Network B receives access requests, fetches a behavioural summary from Network A, and decides one of four access tiers using a hybrid LLM + deterministic safety floor. Runs on port 8002.

## File Map

### `network_b/policy/`

| File | Purpose | Key Functions/Classes |
|------|---------|----------------------|
| `risk_score.py` | Deterministic weighted risk score from summary fields. Maps enum labels to numeric values (HIGH→0.0, LOW→1.0), applies configurable weights (auth 25%, pdu 20%, traffic 20%, anomaly 20%, behaviour 15%). Same summary always produces same score. | `compute_risk_score(summary) → float` in [0, 1] |
| `tier_mapper.py` | Two functions. `risk_to_max_tier(score)`: maps risk to tier (≤0.20→T3, ≤0.50→T2, ≤0.80→T1, >0.80→T0). `apply_safety_floor(tier, summary)`: hard rules that can only clip tier DOWN (recent_anomaly→max T2, auth LOW→max T1, anomalous→max T1). | `risk_to_max_tier()`, `apply_safety_floor()` |
| `llm_client.py` | Calls local Ollama (or cloud LLM) with the summary + access context. System prompt defines tiers and conservative principles. Expects JSON response `{proposed_tier, reasoning, confidence}`. Temperature 0.0. 30s timeout, returns `None` on failure. | `call_llm(summary, context) → LlmProposal \| None` |
| `policy_engine.py` | Three modes: `decide()` (rules-only), `decide_hybrid()` (LLM + safety floor), `decide_auto()` (reads mode from config). Hybrid: compute deterministic tier as fallback, call LLM, apply safety floor to LLM proposal, return `PolicyDecision` with full metadata. | `decide()`, `decide_hybrid()`, `decide_auto()` |

**Safety floor invariant:** The LLM's proposal is always passed through `apply_safety_floor()` which can only tighten (lower tier), never loosen. This defends against prompt injection — even if the LLM says "grant T3", the safety floor clips it based on summary fields.

### `network_b/decision/`

| File | Purpose | Key Functions/Classes |
|------|---------|----------------------|
| `decision_service.py` | End-to-end orchestrator. Fetches summary from Network A via HTTP (`POST :8001/v1/summary/request`). If unreachable → conservative T1. Calls `decide_auto()`, maps tier to simulated enforcement rules (bandwidth caps, monitoring intervals, allowed services), logs decision, returns `AccessDecision`. | `handle_access_request(req) → AccessDecision`, `ENFORCEMENT_MAP` |
| `decision_logger.py` | Writes full decision JSON to `data/access_decisions/{request_id}_{pseudonym}.json`. Includes tier, risk score, reason, LLM metadata, safety floor clips, simulated enforcement, timestamp. | `log_decision(decision)` |

### `network_b/api/`

| File | Purpose |
|------|---------|
| `app.py` | FastAPI app (no lifespan needed — no Postgres). |
| `routes.py` | Two endpoints: `GET /v1/health`, `POST /v1/access/request` → calls `handle_access_request()`. |

## Cross-File Dependencies

```
api/routes.py
  └── decision_service.py
        ├── HTTP → Network A API (fetch summary)
        ├── policy_engine.py
        │     ├── risk_score.py
        │     ├── tier_mapper.py (safety floor)
        │     └── llm_client.py → Ollama HTTP
        └── decision_logger.py → data/access_decisions/
```

## Tier Enforcement (Simulated)

| Tier | Bandwidth | Monitoring | Services |
|------|-----------|------------|----------|
| T0_REJECT | 0 Mbps | N/A | None |
| T1_RESTRICTED | 10 Mbps | 30s intervals | standard_data only |
| T2_MONITORED | 50 Mbps | 60s intervals | standard_data only |
| T3_FULL | Unlimited | None | standard_data, voice, video, iot |
