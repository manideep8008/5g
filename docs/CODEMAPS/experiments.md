# Experiments & Baselines

## Overview

The evaluation framework compares three systems against an oracle dataset of labelled scenarios. Measures accuracy, confusion matrices, severity-weighted error, latency, and prompt-injection resistance.

## File Map

### `experiments/`

| File | Purpose | Key Functions |
|------|---------|---------------|
| `generate_oracle.py` | Generates ~55 unambiguous scenarios by enumerating bucket combinations (auth x pdu x traffic x anomaly x behaviour). Filters to cases far from tier boundaries. Adds ~15 hand-labelled conflicting-signal cases and 5 adversarial prompt-injection scenarios. Outputs `experiments/oracle_dataset.json`. | `generate_oracle()` |
| `run_scenario_experiments.py` | Loads oracle dataset, runs all 3 systems on each scenario with 3 seeds. Records predicted tier, risk score, LLM proposal, latency. Outputs `data/results/experiment_results.json`. | `run_experiments()` |
| `generate_results.py` | Loads experiment results, computes per-system accuracy (overall, per-tier, per-category), 4x4 confusion matrices, severity-weighted error (T3-when-T0 is worst), P50/P95 latency, prompt-injection success rate. Outputs tables to `data/results/`. | `generate_results()` |
| `run_real_ue_demo.py` | Live demo script: sends access request to running Network B API, prints decision. Used with actual UE connected to OAI core. | `run_demo()` |

### `baselines/`

| File | Purpose | What It Tests |
|------|---------|---------------|
| `rule_without_summary.py` | Receives only `AccessRequest` (slice, DNN, service), no behavioural summary. Estimates risk from request context alone (slice_risk + service_risk + base_uncertainty). | Whether behavioural summaries add value over context-only decisions. |
| `single_llm_decision.py` | Has summary + access request. Calls LLM but accepts proposal WITHOUT safety floor. | Whether safety floor is necessary. Should fail prompt-injection tests. |

## Three Systems Compared

| System | Summary? | LLM? | Safety Floor? |
|--------|----------|------|---------------|
| Full (hybrid) | Yes | Yes | Yes |
| rule_without_summary | No | No | N/A |
| single_llm | Yes | Yes | **No** |

## Output Files

```
experiments/oracle_dataset.json          # Input: labelled scenarios
data/results/experiment_results.json     # Raw: per-scenario predictions
data/results/accuracy.json               # Aggregated accuracy stats
data/results/confusion_matrices.json     # 4x4 per system
data/results/severity_weighted_error.json
data/results/latency_stats.json
data/results/injection_stats.json        # Prompt injection success rates
```
