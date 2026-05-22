# Tests — 175 Tests Across 15 Files

## Test Map

| File | Module Under Test | What It Covers |
|------|-------------------|----------------|
| `test_amf_parser.py` | `network_a.collector.amf_log_parser` | All 14 event types parsed correctly, unknown lines return None, timestamp extraction, IMSI extraction, edge cases |
| `test_upf_collector.py` | `network_a.collector.upf_traffic_collector` | Prometheus scraping, delta computation, spike detection, stub fallback when Prometheus unavailable |
| `test_feature_extractor.py` | `network_a.collector.feature_extractor` | Event grouping by IMSI, session record construction, auth/PDU counting, traffic merging |
| `test_identity.py` | `network_a.identity` | HMAC hashing determinism, pseudonym format (`UE_HASH_*`), identity mapper get-or-create |
| `test_db.py` | `network_a.db` | In-memory fallback CRUD operations for all 4 tables |
| `test_profile_builder.py` | `network_a.summary.profile_builder` | Profile aggregation from sessions, failure rate computation, empty session handling |
| `test_risk_flag_generator.py` | `network_a.summary.risk_flag_generator` | Bucketization thresholds (boundary values), overall risk weighting, behaviour label classification |
| `test_summary_generator.py` | `network_a.summary.summary_generator` | End-to-end summary generation, field allowlist enforcement, disclosure logging |
| `test_summary_schema.py` | `network_a.summary.summary_schema` | Pydantic model validation, enum serialisation, required fields |
| `test_policy_engine.py` | `network_b.policy.policy_engine` | Rules-only decisions, auto mode config reading, deterministic reproducibility |
| `test_hybrid_policy.py` | `network_b.policy.policy_engine` | Hybrid mode with mocked LLM, safety floor clipping of LLM proposals, fallback when LLM unavailable |
| `test_llm_client.py` | `network_b.policy.llm_client` | Prompt construction, JSON response parsing, timeout handling, malformed response handling |
| `test_prompt_injection.py` | `network_b.policy` | 5 adversarial scenarios where LLM is tricked into proposing T3, verifies safety floor clips to correct tier |
| `test_baselines.py` | `baselines/` | rule_without_summary risk estimation, single_llm without safety floor |
| `test_evaluation.py` | `experiments/` | Oracle generation validity, experiment runner output format, results computation |

## Running Tests

```bash
pytest tests/ -v              # Full verbose output
pytest tests/ -q              # Quick summary
pytest tests/test_prompt_injection.py -v   # Just security tests
```

## Key Testing Patterns

- **In-memory fallback**: All tests run without Postgres by using the in-memory fallback in `db.py`
- **LLM mocking**: `test_hybrid_policy.py` and `test_llm_client.py` mock the HTTP call to Ollama
- **Determinism**: `test_policy_engine.py` verifies same input always produces same output
- **Boundary values**: `test_risk_flag_generator.py` tests exact threshold boundaries (e.g., 0.05 vs 0.0500001)
