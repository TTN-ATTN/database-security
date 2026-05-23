#!/usr/bin/env bash
# Phase 5 - Performance Monitoring verification.
# Checks alert rules, runs load + stress tests, confirms metrics are flowing.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -f .env ]; then
  echo "Missing .env. Create it with: cp .env.example .env" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

if [ -d ".venv" ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${NC} $*"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; }
info() { echo -e "  ${YELLOW}[INFO]${NC} $*"; }

PROM_URL="http://127.0.0.1:${PROMETHEUS_HOST_PORT:-9090}"
GRAFANA_URL="http://127.0.0.1:${GRAFANA_HOST_PORT:-3000}"

# ── step 1: check Prometheus is up ──
echo ""
echo "=== Step 1: Prometheus readiness ==="
if curl -sf "${PROM_URL}/-/ready" > /dev/null 2>&1; then
    ok "Prometheus is ready at ${PROM_URL}"
else
    fail "Prometheus is not ready at ${PROM_URL}"
    exit 1
fi

# ── step 2: check Phase 5 alert rules are loaded ──
echo ""
echo "=== Step 2: Phase 5 alert rules ==="
RULES_JSON=$(curl -sf "${PROM_URL}/api/v1/rules" 2>/dev/null || echo '{}')
P5_ALERTS=$(echo "$RULES_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
groups = data.get('data', {}).get('groups', [])
count = 0
for g in groups:
    if g.get('name') == 'phase5-performance':
        for r in g.get('rules', []):
            print(f\"  - {r['name']}\")
            count += 1
print(f'TOTAL:{count}')
" 2>/dev/null || echo "TOTAL:0")

P5_COUNT=$(echo "$P5_ALERTS" | grep '^TOTAL:' | cut -d: -f2)
echo "$P5_ALERTS" | grep -v '^TOTAL:'
if [ "${P5_COUNT:-0}" -ge 5 ]; then
    ok "${P5_COUNT} Phase 5 alert rules loaded"
else
    fail "Expected >=5 Phase 5 alert rules, found ${P5_COUNT:-0}"
    info "Try reloading Prometheus: curl -X POST ${PROM_URL}/-/reload"
fi

# ── step 3: check Grafana health ──
echo ""
echo "=== Step 3: Grafana health ==="
if curl -sf "${GRAFANA_URL}/api/health" > /dev/null 2>&1; then
    ok "Grafana is healthy at ${GRAFANA_URL}"
else
    fail "Grafana is not reachable"
fi

# ── step 4: check MySQL exporter target is up ──
echo ""
echo "=== Step 4: MySQL exporter scrape ==="
UP_VAL=$(curl -sf "${PROM_URL}/api/v1/query?query=up%7Bjob%3D%22mysql%22%7D" 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['result'][0]['value'][1])" 2>/dev/null || echo "0")
if [ "$UP_VAL" = "1" ]; then
    ok "MySQL exporter target is UP"
else
    fail "MySQL exporter target is DOWN (up=$UP_VAL)"
fi

# ── step 5: run load test ──
echo ""
echo "=== Step 5: Load test (45s) ==="
info "Running phase5_generate_load.py ..."
if python3 scripts/phase5_generate_load.py --duration 45 --select-workers 4 --write-workers 2 --slow-workers 1; then
    echo ""
    ok "Load test completed"
else
    echo ""
    fail "Load test exited with errors (non-zero exit code)"
fi

# ── step 6: run connection stress test ──
echo ""
echo "=== Step 6: Connection stress test ==="
info "Running phase5_stress_connections.py ..."
if python3 scripts/phase5_stress_connections.py --count 80 --hold 15; then
    echo ""
    ok "Connection stress test completed"
else
    echo ""
    fail "Connection stress test exited with errors"
fi

# ── step 7: verify key metrics have data ──
echo ""
echo "=== Step 7: Verify key metrics ==="
check_metric() {
    local metric="$1"
    local label="$2"
    local val
    val=$(curl -sf "${PROM_URL}/api/v1/query?query=${metric}" 2>/dev/null \
        | python3 -c "
import sys, json
d = json.load(sys.stdin)
results = d.get('data', {}).get('result', [])
if results:
    print(results[0]['value'][1])
else:
    print('N/A')
" 2>/dev/null || echo "N/A")
    if [ "$val" != "N/A" ] && [ "$val" != "0" ]; then
        ok "${label} = ${val}"
    else
        info "${label} = ${val} (may need more time for scrape)"
    fi
}

check_metric "mysql_global_status_threads_connected" "Threads connected"
check_metric "mysql_global_status_slow_queries" "Slow queries (total)"
check_metric "rate(mysql_global_status_questions[2m])" "QPS (2m rate)"
check_metric "mysql_global_status_innodb_buffer_pool_read_requests" "InnoDB buffer pool read requests"
check_metric "mysql_global_status_bytes_sent" "Bytes sent (total)"

# ── step 8: check if any Phase 5 alerts are firing ──
echo ""
echo "=== Step 8: Phase 5 alert status ==="
FIRING=$(echo "$RULES_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
groups = data.get('data', {}).get('groups', [])
firing = []
for g in groups:
    if g.get('name') == 'phase5-performance':
        for r in g.get('rules', []):
            if r.get('state') == 'firing':
                firing.append(r['name'])
            elif r.get('state') == 'pending':
                firing.append(f\"{r['name']} (pending)\")
if firing:
    for f in firing:
        print(f'  - {f}')
else:
    print('  (none currently firing)')
" 2>/dev/null || echo "  (could not query)")

# Re-fetch rules for freshest state
RULES_JSON_FRESH=$(curl -sf "${PROM_URL}/api/v1/rules" 2>/dev/null || echo '{}')
echo "$RULES_JSON_FRESH" | python3 -c "
import sys, json
data = json.load(sys.stdin)
groups = data.get('data', {}).get('groups', [])
firing = []
for g in groups:
    if g.get('name') in ('phase5-performance', 'phase1-baseline'):
        for r in g.get('rules', []):
            if r.get('state') in ('firing', 'pending'):
                firing.append(f\"  - {r['name']} ({r['state']})\")
if firing:
    for f in firing:
        print(f)
else:
    print('  (none currently firing)')
" 2>/dev/null || echo "  (could not query)"
info "Alerts may take 1-2 minutes to transition to firing after load."

# ── summary ──
echo ""
echo "=== Phase 5 Summary ==="
ok "Phase 5 Performance Monitoring verification complete."
info "Open Grafana at ${GRAFANA_URL} -> Dashboard 'Database Security - Phase 5 Performance'"
info "Check Prometheus alerts at ${PROM_URL}/alerts"
echo ""
