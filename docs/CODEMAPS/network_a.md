# Network A — Data Collection & Summary Generation

## Overview

Network A wraps a real OAI CN5G core. It collects UE behaviour from AMF logs and UPF metrics, stores session records in Postgres, and serves privacy-preserving behavioural summaries via a FastAPI endpoint on port 8001.

## File Map

### `network_a/collector/`

| File | Purpose | Key Functions/Classes |
|------|---------|----------------------|
| `collector_main.py` | Long-running service entry point. Runs two concurrent async tasks: tail AMF logs + scrape UPF Prometheus. Groups AMF events by IMSI, waits for CONTEXT_RELEASE, then calls feature extractor. | `run_collector()`, `tail_amf_log()`, `scrape_upf_loop()` |
| `amf_log_parser.py` | Regex-parses raw OAI AMF log lines into structured events. Handles 14 event types (REGISTRATION_REQUEST, AUTH_SUCCESS, AUTH_FAILURE, PDU_REQUEST, CONTEXT_RELEASE, etc.). Returns `None` for unrecognised lines. | `parse_amf_line(line) → AmfEvent \| None`, `AmfEvent` dataclass |
| `feature_extractor.py` | Joins AMF events + UPF snapshots into a `SessionRecord`. Groups events by IMSI, counts auth/PDU attempts and failures, merges traffic data, persists to Postgres. | `extract_session(events, upf_snapshots) → SessionRecord` |
| `upf_traffic_collector.py` | Scrapes UPF Prometheus endpoint for per-UE traffic counters. Computes delta throughput, detects traffic spikes (>1000 kbps AND >3x average). Falls back to stub data if Prometheus unavailable. | `scrape_upf(url) → list[UpfSnapshot]`, `UpfSnapshot` dataclass |

**Data flow:** AMF logs → `amf_log_parser` → events grouped by IMSI → `feature_extractor` merges with UPF snapshots → `SessionRecord` stored in Postgres.

### `network_a/identity/`

| File | Purpose | Key Functions/Classes |
|------|---------|----------------------|
| `ue_hasher.py` | HMAC-SHA256 pseudonymisation. IMSI → `UE_HASH_<12-char-hex>`. Key from `HMAC_SECRET_KEY` env var. | `hash_imsi(imsi) → str` |
| `identity_mapper.py` | Wraps hasher, stores IMSI↔pseudonym mapping in Postgres. Falls back to in-memory dict. | `get_or_create_pseudonym(imsi) → str` |

### `network_a/summary/`

| File | Purpose | Key Functions/Classes |
|------|---------|----------------------|
| `summary_schema.py` | Pydantic models (data contracts). Defines all enums (`Tier`, `AuthStability`, `TrafficPattern`, `BehaviourLabel`) and request/response models. Shared across both networks. | `UeBehaviouralSummary`, `SummaryRequest`, `SummaryResponse`, `AccessRequest`, `AccessDecision` |
| `profile_builder.py` | Aggregates last N sessions (default 200, window 86400s) into a `UeProfile`: auth failure rate, PDU failure rate, peak throughput, spike rate, known slices/DNNs, active risk flags. | `build_profile(pseudonym) → UeProfile` |
| `risk_flag_generator.py` | Bucketises raw profile metrics into categorical labels using thresholds from `config/network_a_config.yaml`. Computes weighted overall risk score. | `classify_auth_stability()`, `classify_pdu_stability()`, `classify_traffic_pattern()`, `compute_overall_risk()`, `classify_behaviour_label()` |
| `summary_generator.py` | Main orchestrator. Validates requested fields against allowlist, builds profile, bucketises, computes risk, logs disclosure to Postgres, returns `SummaryResponse`. | `generate_summary(request) → SummaryResponse` |

**Data flow:** `profile_builder` reads sessions from Postgres → `risk_flag_generator` bucketises → `summary_generator` wraps in response + audit logs.

### `network_a/db.py`

Async Postgres connection pool (asyncpg). 4 tables: `ue_identity`, `ue_session`, `ue_risk_flag`, `summary_disclosure`. Every CRUD operation falls back to in-memory dict if Postgres unavailable.

### `network_a/api/`

| File | Purpose |
|------|---------|
| `app.py` | FastAPI app with lifespan hook (init/close Postgres pool on startup/shutdown). |
| `routes.py` | Two endpoints: `GET /v1/health`, `POST /v1/summary/request` → calls `generate_summary()`. |

## Cross-File Dependencies

```
collector_main.py
  ├── amf_log_parser.py
  ├── upf_traffic_collector.py
  ├── feature_extractor.py
  │     └── db.py (store sessions)
  └── identity/ue_hasher.py

api/routes.py
  └── summary_generator.py
        ├── profile_builder.py → db.py (read sessions)
        ├── risk_flag_generator.py → config/network_a_config.yaml
        ├── identity_mapper.py → ue_hasher.py
        └── db.py (log disclosure)
```
