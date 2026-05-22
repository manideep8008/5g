# Infrastructure — Docker, Config, Scripts, Database

## Docker Compose (`docker-compose.yml`)

Two services that join the OAI core's external network (`oai-cn5g-public-net`):

| Service | Image | IP | Port | Purpose |
|---------|-------|----|------|---------|
| postgres | postgres:16-alpine | 192.168.70.140 | 5432 | Session storage, identity, risk flags, audit log |
| redis | redis:7-alpine | 192.168.70.141 | 6379 | (Available for caching, not heavily used yet) |

Schema initialised via `schema.sql` mounted to `/docker-entrypoint-initdb.d/`.

## Database Schema (`schema.sql`)

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `ue_identity` | IMSI↔pseudonym mapping | pseudonym (PK), imsi_hmac, first_seen, network_b_id |
| `ue_session` | Per-session behaviour records | pseudonym (FK), started_at, duration_sec, auth_attempts, auth_failures, pdu_attempts, pdu_failures, bytes_uplink, bytes_downlink, peak_throughput_kbps, spike_count, cell_id |
| `ue_risk_flag` | Active risk flags per UE | pseudonym (FK), flag_type, severity, evidence, cleared_at |
| `summary_disclosure` | Audit log of every summary served | request_id, pseudonym, network_b_id, disclosed_at, summary_payload, requested_fields |

## Config Files

### `config/network_a_config.yaml`

- `collector.amf_log_path` — where AMF logs are written
- `collector.upf_prometheus_url` — UPF metrics endpoint
- `bucketization` — thresholds for each label category:
  - auth_stability: HIGH (<5% failure), MEDIUM (<20%), LOW (>=20%)
  - pdu_session_stability: same thresholds
  - traffic_pattern: STABLE (<10% spike rate), MODERATE (<30%), VOLATILE (>=30%)
  - behaviour_label: NORMAL (<0.20 risk), SUSPICIOUS (<0.50), ANOMALOUS (>=0.50)
- `summary.default_window_sec` — 86400 (1 day)
- `summary.max_requested_fields` — allowlist of 6 fields

### `config/network_b_policy.yaml`

- `policy.mode` — `hybrid` | `rules_only` | `llm_only`
- `risk_weights` — per-field weights summing to 1.0
- `tier_thresholds` — risk score boundaries for each tier
- `safety_floor.hard_rules` — conditions that force tier clipping
- `llm` — model name, temperature (0.0), base_url (Ollama), timeout

### `.env` / `.env.example`

Postgres credentials, Redis host, HMAC key, Network A/B ports and URLs, AMF log path, UPF Prometheus URL, Ollama endpoint, LLM model name.

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/start_with_oai.sh` | Main entry point. Verifies OAI core is running, captures AMF logs from Docker, starts collector + Network A API (:8001) + Network B API (:8002). Supports `--no-collect` flag. |
| `scripts/run_demo.sh` | Runs end-to-end demo (seed data + access request). |
| `scripts/run_evaluation.sh` | Full evaluation pipeline: generate oracle → run experiments → generate results. |
| `scripts/reproduce.sh` | One-command reproducibility: install deps, run tests, run evaluation. |
| `scripts/seed_demo_data.py` | Seeds Postgres with sample sessions for demo/testing. |
