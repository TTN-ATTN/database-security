#!/usr/bin/env bash
# Phase 3 verification: confirm MySQL active monitor (general + slow log) is wired up,
# generate audit traffic, and parse the logs into evidence.
#
# update from phase 4: steps 9-10 add two more Active Monitor sources when the Phase 4
# services are running - ProxySQL query-digest stats (proxy-layer attribution) and the
# acra-server integrity-chained audit log (encryption-gateway audit trail). Both are
# skipped gracefully if those containers are not up.
#
# Run from the project root:
#   bash scripts/phase3_check.sh

set -euo pipefail

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

CONTAINER="dbsec-mysql"
ROOT_PASS="${MYSQL_ROOT_PASSWORD:-rootpass}"
GENERAL_LOG="logs/mysql/general.log"
SLOW_LOG="logs/mysql/slow.log"

echo "== 1. Confirm general_log + slow_query_log are ON in MySQL =="
docker exec "$CONTAINER" mysql -uroot -p"$ROOT_PASS" -N -e "
  SELECT VARIABLE_NAME, VARIABLE_VALUE
  FROM performance_schema.global_variables
  WHERE VARIABLE_NAME IN ('general_log', 'slow_query_log', 'long_query_time', 'log_output');
"

echo
echo "== 2. Confirm log files exist inside container =="
docker exec "$CONTAINER" ls -l /var/log/mysql/

echo
echo "== 3. Generate audit traffic =="
if [ -d ".venv" ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi
python3 scripts/phase3_generate_audit_queries.py

echo
echo "== 4. Flush logs so file mirrors current buffer =="
docker exec "$CONTAINER" mysql -uroot -p"$ROOT_PASS" -e "FLUSH LOGS;"

echo
echo "== 5. Verify log files on host are non-empty =="
if [ ! -s "$GENERAL_LOG" ]; then
  echo "[FAIL] $GENERAL_LOG is empty or missing." >&2
  exit 1
fi
if [ ! -s "$SLOW_LOG" ]; then
  echo "[WARN] $SLOW_LOG is empty (slow queries may not have crossed long_query_time)."
fi
echo "general.log size: $(wc -c <"$GENERAL_LOG") bytes"
[ -s "$SLOW_LOG" ] && echo "slow.log    size: $(wc -c <"$SLOW_LOG") bytes"

echo
echo "== 6. Parse logs into structured audit evidence =="
python3 scripts/phase3_parse_audit_log.py

echo
echo "== 7. Sample evidence rows: denied appuser PII access =="
grep -E "phase3:pii-access-denied-appuser" "$GENERAL_LOG" | head -n 5 || true

echo
echo "== 8. Sample evidence rows: abnormal root operations =="
grep -E "phase3:abnormal-root" "$GENERAL_LOG" | head -n 5 || true

# ----- update from phase 4: extra Active Monitor sources (proxy + encryption gateway) -----
# These are optional and only run if the Phase 4 services are up. MySQL's general_log
# loses per-client attribution behind ProxySQL, so the proxy's own digest stats are the
# real proxy-layer audit trail; acra-server's integrity-chained log is the encryption
# gateway's audit trail.

echo
echo "== 9. (Phase 4 source) ProxySQL data-plane audit =="
if docker ps --filter name=dbsec-proxysql --format '{{.Names}}' | grep -q dbsec-proxysql; then
  python3 scripts/phase3_collect_proxysql_audit.py
else
  echo "[SKIP] dbsec-proxysql not running."
fi

echo
echo "== 10. (Phase 4 source) Acra audit log (integrity-chained) =="
if docker ps --filter name=dbsec-acra-server --format '{{.Names}}' | grep -q dbsec-acra-server; then
  mkdir -p logs/acra
  docker logs dbsec-acra-server 2>&1 | grep "integrity=" > logs/acra/acra_audit.log || true
  lines=$(wc -l < logs/acra/acra_audit.log)
  echo "Collected $lines integrity-chained audit lines -> logs/acra/acra_audit.log"
  tail -n 3 logs/acra/acra_audit.log || true
else
  echo "[SKIP] dbsec-acra-server not running (encryption eval path)."
fi

echo
echo "Phase 3 active-monitor checks passed."
echo "Evidence (MySQL):    logs/mysql/general.log, logs/mysql/slow.log,"
echo "                     logs/mysql/audit_report.json, logs/mysql/audit_summary.csv"
echo "Evidence (Phase 4):  logs/proxysql/proxysql_audit.json/.csv (if ProxySQL up),"
echo "                     logs/acra/acra_audit.log (if acra-server up)"
