#!/usr/bin/env bash
set -euo pipefail

# Start IBN-ZTA services alongside a running OAI CN5G core.
#
# Prerequisites:
#   1. OAI core is up:  docker compose up -d
#   2. .env file exists (copy from .env.example)
#   3. Python venv active with requirements.txt installed
#   4. UPF metrics enabled in conf/config.yaml:
#        register_nf:
#          general:
#            metrics:
#              enabled: true
#              port: 9090
#
# Usage:
#   ./scripts/start_with_oai.sh              # collector + both APIs
#   ./scripts/start_with_oai.sh --no-collect  # APIs only (skip collector)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

source .env 2>/dev/null || true
export PYTHONPATH="$PROJECT_DIR"

SKIP_COLLECTOR=false
for arg in "$@"; do
    case $arg in
        --no-collect) SKIP_COLLECTOR=true ;;
    esac
done

PIDS=()

cleanup() {
    echo ""
    echo "Shutting down IBN-ZTA services..."
    # Stop AMF log capture
    if [ -n "${AMF_LOG_PID:-}" ]; then
        kill "$AMF_LOG_PID" 2>/dev/null || true
    fi
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    echo "Done."
}
trap cleanup EXIT INT TERM

# ─── Verify OAI core is running ───────────────────────────────

echo "Checking OAI CN5G core..."
if ! docker ps --format '{{.Names}}' | grep -q "oai-amf"; then
    echo "ERROR: oai-amf container not running."
    echo "Start the core first:  docker compose up -d"
    exit 1
fi
echo "  oai-amf:  running"

if docker ps --format '{{.Names}}' | grep -q "oai-upf"; then
    echo "  oai-upf:  running"
else
    echo "  oai-upf:  NOT running (UPF metrics will be unavailable)"
fi

if docker ps --format '{{.Names}}' | grep -q "ibn-zta-postgres"; then
    echo "  postgres: running"
else
    echo "  postgres: NOT running (using in-memory fallback)"
fi
echo ""

# ─── Capture AMF logs from Docker ─────────────────────────────

mkdir -p data/logs

AMF_LOG="${AMF_LOG_PATH:-data/logs/amf_live.log}"
echo "Capturing AMF logs → $AMF_LOG"
docker logs -f oai-amf 2>&1 > "$AMF_LOG" &
AMF_LOG_PID=$!
sleep 1

# ─── Start Collector (optional) ───────────────────────────────

if [ "$SKIP_COLLECTOR" = false ]; then
    UPF_URL="${UPF_PROMETHEUS_URL:-http://localhost:9090/metrics}"
    echo "Starting Behaviour Collector (amf=$AMF_LOG, upf=$UPF_URL)..."
    python3 -m network_a.collector.collector_main \
        --amf-log "$AMF_LOG" \
        --upf-url "$UPF_URL" &
    PIDS+=($!)
    sleep 1
fi

# ─── Start Network A API ──────────────────────────────────────

NA_PORT="${NETWORK_A_PORT:-8001}"
echo "Starting Network A API on port $NA_PORT..."
python3 -m uvicorn network_a.api.app:app \
    --host 0.0.0.0 --port "$NA_PORT" --log-level info &
PIDS+=($!)

# ─── Start Network B API ──────────────────────────────────────

NB_PORT="${NETWORK_B_PORT:-8002}"
echo "Starting Network B API on port $NB_PORT..."
python3 -m uvicorn network_b.api.app:app \
    --host 0.0.0.0 --port "$NB_PORT" --log-level info &
PIDS+=($!)

# ─── Wait for APIs to be ready ─────────────────────────────────

echo ""
echo "Waiting for APIs..."
sleep 3

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  IBN-ZTA services running"
echo ""
echo "  Network A (summary provider): http://localhost:$NA_PORT/v1/health"
echo "  Network B (policy engine):    http://localhost:$NB_PORT/v1/health"
echo "  AMF log capture:              $AMF_LOG"
echo ""
echo "  Press Ctrl+C to stop all services"
echo "════════════════════════════════════════════════════════════"

wait
