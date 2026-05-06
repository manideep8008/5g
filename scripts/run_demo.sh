#!/usr/bin/env bash
set -euo pipefail

# End-to-end demo script.
#
# Usage:
#   ./scripts/run_demo.sh          # Local mode (no servers needed)
#   ./scripts/run_demo.sh --live   # Live mode (starts servers, seeds DB)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

MODE="local"
for arg in "$@"; do
    case $arg in
        --live) MODE="live" ;;
    esac
done

if [ "$MODE" = "local" ]; then
    echo "Running demo in local mode (no servers needed)..."
    echo ""
    PYTHONPATH="$PROJECT_DIR" python3 -m experiments.run_real_ue_demo
    exit 0
fi

# Live mode — start servers
cleanup() {
    echo ""
    echo "Shutting down servers..."
    kill "$PID_A" "$PID_B" 2>/dev/null || true
    wait "$PID_A" "$PID_B" 2>/dev/null || true
}
trap cleanup EXIT

echo "Starting Network A on port 8001..."
PYTHONPATH="$PROJECT_DIR" python3 -m uvicorn network_a.api.app:app --port 8001 --log-level warning &
PID_A=$!

echo "Starting Network B on port 8002..."
PYTHONPATH="$PROJECT_DIR" python3 -m uvicorn network_b.api.app:app --port 8002 --log-level warning &
PID_B=$!

echo "Waiting for servers to start..."
sleep 3

echo "Seeding demo data..."
PYTHONPATH="$PROJECT_DIR" python3 -m scripts.seed_demo_data
echo ""

PYTHONPATH="$PROJECT_DIR" python3 -m experiments.run_real_ue_demo --live
