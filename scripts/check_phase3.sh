#!/usr/bin/env bash
# Phase 3 verification: confirm MySQL active monitor (general + slow log) is wired up,
# generate audit traffic, and parse the logs into evidence.
#
# Run from the project root:
#   bash scripts/check_phase3.sh

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
python3 scripts/generate_audit_queries.py

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
python3 scripts/parse_audit_log.py

echo
echo "== 7. Sample evidence rows: denied appuser PII access =="
grep -E "phase3:pii-access-denied-appuser" "$GENERAL_LOG" | head -n 5 || true

echo
echo "== 8. Sample evidence rows: abnormal root operations =="
grep -E "phase3:abnormal-root" "$GENERAL_LOG" | head -n 5 || true

echo
echo "Phase 3 active-monitor checks passed."
echo "Evidence: logs/mysql/general.log, logs/mysql/slow.log,"
echo "          logs/mysql/audit_report.json, logs/mysql/audit_summary.csv"
