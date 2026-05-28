#!/usr/bin/env bash
# Phase 7 - Bring up the FULL integrated path:
#   Client -> ProxySQL (DBF) -> Acra (encrypt) -> ha-router (GR) -> MySQL Cluster
#
# Prereqs: ACRA_MASTER_KEY in .env (make acra-keys). The HA cluster is bootstrapped by
# this script if it isn't already healthy.
#
# Run from the project root:
#   bash scripts/phase7_full_up.sh

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
set -a; [ -f .env ] && . ./.env; set +a

if ! grep -q '^ACRA_MASTER_KEY=' .env; then
  echo "ACRA_MASTER_KEY not in .env. Run: make acra-keys" >&2
  exit 1
fi

FILES="-f compose.yaml -f compose.chained.yaml -f compose.ha.yaml -f compose.full.yaml"
PROFILES="--profile acra --profile ha"

echo "== 1. Ensure HA cluster is up & healthy =="
online=$(docker exec dbsec-mysql-1 mysql -uroot -p"${MYSQL_ROOT_PASSWORD:-rootpass}" -N 2>/dev/null \
  -e "SELECT COUNT(*) FROM performance_schema.replication_group_members WHERE MEMBER_STATE='ONLINE';" || echo 0)
if [ "${online:-0}" != "3" ]; then
  echo "  cluster not fully online (${online:-0}/3) -> bootstrapping"
  bash scripts/phase7_ha_bootstrap.sh
else
  echo "  cluster already 3/3 ONLINE"
fi

echo
echo "== 2. Bring up full integrated path =="
# shellcheck disable=SC2086
docker compose $FILES $PROFILES up -d

echo
echo "== 3. Wait for front ProxySQL admin + load DBF rules =="
for i in $(seq 1 30); do
  if docker exec dbsec-mysql mysql --ssl-mode=DISABLED -h dbsec-proxysql -P 6032 \
       -uradmin -pradmin -e "SELECT 1" >/dev/null 2>&1; then break; fi
  sleep 1
done
bash scripts/phase4_proxysql_setup.sh >/dev/null

echo
echo "== 4. Path wiring =="
echo "  front ProxySQL (6033) backend:"
docker exec dbsec-mysql mysql --ssl-mode=DISABLED -h dbsec-proxysql -P 6032 \
  -uradmin -pradmin -N 2>/dev/null -e "SELECT hostname,port FROM runtime_mysql_servers;" \
  | sed 's/^/    /'
echo "  (Acra -> dbsec-ha-router:6033 -> cluster primary)"

echo
echo "Full integrated path is up. Verify with:"
echo "  python3 scripts/phase7_full_verify.py"
echo "Revert front ProxySQL to default:  bash scripts/phase7_chain_down.sh"
