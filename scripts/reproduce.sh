#!/usr/bin/env bash
set -euo pipefail

# Reproduce all results from scratch.
# This script regenerates everything needed for the paper:
#   1. Oracle dataset from bucket-space enumeration
#   2. Deterministic evaluation (no external dependencies)
#   3. Results tables and figures
#   4. Demo run
#
# Usage: ./scripts/reproduce.sh
#
# Requirements: Python 3.11+, pip packages from requirements.txt
# No Ollama, no Postgres, no Docker needed — uses in-memory fallbacks.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "============================================================"
echo "IBN-ZTA — Full Reproduction Pipeline"
echo "============================================================"
echo "  Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Python:  $(python3 --version)"
echo ""

# Step 0: Verify dependencies
echo "[0/6] Checking dependencies..."
python3 -c "import fastapi, pydantic, httpx, yaml" 2>/dev/null || {
    echo "  Installing dependencies..."
    pip3 install -q -r requirements.txt
}
echo "  OK"
echo ""

# Step 1: Run tests
echo "[1/6] Running test suite (175 tests)..."
python3 -m pytest tests/ -q --tb=line
echo ""

# Step 2: Generate oracle
echo "[2/6] Generating oracle dataset..."
python3 -m experiments.generate_oracle
echo ""

# Step 3: Run deterministic evaluation
echo "[3/6] Running deterministic evaluation (3 seeds)..."
python3 -m experiments.run_scenario_experiments --seeds 3 --no-llm
echo ""

# Step 4: Generate results
echo "[4/6] Generating evaluation results..."
python3 -m experiments.generate_results
echo ""

# Step 5: Run demo
echo "[5/6] Running end-to-end demo..."
python3 -m experiments.run_real_ue_demo
echo ""

# Step 6: Summary
echo "[6/6] Listing outputs..."
echo ""
echo "Generated files:"
echo "  experiments/oracle_dataset.json     — Oracle dataset (70 scenarios)"
echo "  data/results/experiment_results.json — Raw experiment runs (630 runs)"
echo "  data/results/accuracy.json          — Per-system accuracy"
echo "  data/results/confusion_matrices.json — 4×4 confusion matrices"
echo "  data/results/severity_weighted_error.json — Severity scores"
echo "  data/results/latency_stats.json     — P50/P95 latency"
echo "  data/results/injection_stats.json   — Injection success rates"
echo ""
echo "============================================================"
echo "Reproduction complete!"
echo "  Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""
echo "To reproduce with LLM (requires Ollama + llama3.1:8b-instruct):"
echo "  ollama pull llama3.1:8b-instruct-q4_K_M"
echo "  ./scripts/run_evaluation.sh --with-llm"
echo "============================================================"
