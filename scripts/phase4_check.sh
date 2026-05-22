#!/usr/bin/env bash
# Phase 4 verification: Database Firewall (ProxySQL) + Acra transparent encryption.
#
# Mandatory: ProxySQL DBF (main demo path).
# Optional:  Acra transparent encryption (evaluation path) - only checked if
#            dbsec-acra-server is running.
#
# Run from the project root:
#   bash scripts/phase4_check.sh

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

ADMIN_USER="${PROXYSQL_ADMIN_USER:-radmin}"
ADMIN_PASS="${PROXYSQL_ADMIN_PASSWORD:-radmin}"

py() { if [ -d .venv ]; then . .venv/bin/activate; fi; python3 "$@"; }
padmin() {
  docker exec dbsec-mysql mysql --ssl-mode=DISABLED -h dbsec-proxysql -P 6032 \
    -u"$ADMIN_USER" -p"$ADMIN_PASS" "$@" 2>/dev/null
}

echo "==================== Phase 4: Database Firewall (ProxySQL) ===================="

echo
echo "== 1. ProxySQL container is up =="
docker ps --filter name=dbsec-proxysql --format '{{.Names}} {{.Status}}'

echo
echo "== 2. Ensure DBF deny rules are loaded =="
bash scripts/phase4_proxysql_setup.sh >/dev/null
padmin -t -e "SELECT rule_id, match_pattern, error_msg FROM runtime_mysql_query_rules ORDER BY rule_id;"

echo
echo "== 3. DBF allow/deny behavior test =="
py scripts/phase4_dbf_test.py

echo
echo "== 4. ProxySQL firewall evidence: rule hit counters =="
# Counters reset when rules were (re)loaded in step 2, so these reflect the deny hits
# from the step 3 test run. ProxySQL flushes rule stats on a ~1-2s interval, so wait.
sleep 2
padmin -t -e "SELECT rule_id, hits FROM stats_mysql_query_rules ORDER BY rule_id;"

echo
echo "==================== Phase 4: Acra Transparent Encryption ===================="
if docker ps --filter name=dbsec-acra-server --format '{{.Names}}' | grep -q dbsec-acra-server; then
  echo
  echo "== 5. acra-server is up =="
  docker ps --filter name=dbsec-acra-server --format '{{.Names}} {{.Status}}'
  echo
  echo "== 6. Transparent encryption round-trip test =="
  py scripts/phase4_encryption_test.py
else
  echo
  echo "[SKIP] acra-server is not running (evaluation path, optional)."
  echo "       Enable it with:"
  echo "         bash scripts/phase4_acra_keys.sh"
  echo "         docker compose --profile acra up -d acra-server"
fi

echo
echo "Phase 4 checks passed."
