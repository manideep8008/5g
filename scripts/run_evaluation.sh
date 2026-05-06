#!/usr/bin/env bash
set -euo pipefail

# One-command full evaluation pipeline.
# Usage: ./scripts/run_evaluation.sh [--with-llm]
#
# Without --with-llm: runs deterministic evaluation only (fast, no Ollama needed)
# With --with-llm: runs full hybrid evaluation (requires Ollama with llama3.1)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

WITH_LLM=false
SEEDS=3

for arg in "$@"; do
    case $arg in
        --with-llm) WITH_LLM=true ;;
        --seeds=*) SEEDS="${arg#*=}" ;;
    esac
done

echo "============================================================"
echo "IBN-ZTA Evaluation Pipeline"
echo "============================================================"
echo "  Project dir: $PROJECT_DIR"
echo "  Mode: $([ "$WITH_LLM" = true ] && echo 'HYBRID (LLM + rules)' || echo 'DETERMINISTIC (rules only)')"
echo "  Seeds: $SEEDS"
echo "  Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# Step 1: Generate oracle dataset
echo "[1/4] Generating oracle dataset..."
python3 -m experiments.generate_oracle
echo ""

# Step 2: Run tests to verify system integrity
echo "[2/4] Running test suite..."
python3 -m pytest tests/ -q --tb=line
echo ""

# Step 3: Run experiments
echo "[3/4] Running experiments..."
if [ "$WITH_LLM" = true ]; then
    python3 -m experiments.run_scenario_experiments --seeds "$SEEDS"
else
    python3 -m experiments.run_scenario_experiments --seeds "$SEEDS" --no-llm
fi
echo ""

# Step 4: Generate results
echo "[4/4] Generating results..."
python3 -m experiments.generate_results
echo ""

echo "============================================================"
echo "Evaluation complete!"
echo "  Results: data/results/"
echo "  Oracle:  experiments/oracle_dataset.json"
echo "  Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"
