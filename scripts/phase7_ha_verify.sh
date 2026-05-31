#!/usr/bin/env bash
# Phase 7 - Verify the HA cluster is healthy and the GR router tracks the primary.
# Does NOT trigger failover (use phase7_ha_failover.py for that).
#
# Run from the project root:
#   bash scripts/phase7_ha_verify.sh

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
set -a; [ -f .env ] && . ./.env; set +a
ROOTPW="${MYSQL_ROOT_PASSWORD:-rootpass}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${NC} $*"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; }
info() { echo -e "  ${YELLOW}[INFO]${NC} $*"; }

echo "==================== Phase 7: HA Verification ===================="

echo
echo "== 1. Group members =="
docker exec dbsec-mysql-1 mysql -uroot -p"$ROOTPW" -t 2>/dev/null -e \
  "SELECT MEMBER_HOST AS host, MEMBER_STATE AS state, MEMBER_ROLE AS role
   FROM performance_schema.replication_group_members ORDER BY MEMBER_HOST;"
ONLINE=$(docker exec dbsec-mysql-1 mysql -uroot -p"$ROOTPW" -N 2>/dev/null -e \
  "SELECT COUNT(*) FROM performance_schema.replication_group_members WHERE MEMBER_STATE='ONLINE';")
if [ "${ONLINE:-0}" = "3" ]; then ok "3/3 members ONLINE"; else fail "${ONLINE:-0}/3 members ONLINE"; fi

echo
echo "== 2. ProxySQL GR router hostgroups (HG2=writer/primary, HG3=reader) =="
docker exec dbsec-mysql-1 mysql --ssl-mode=DISABLED -h dbsec-ha-router -P 6032 \
  -uradmin -pradmin -t 2>/dev/null \
  -e "SELECT hostgroup_id, hostname, status FROM runtime_mysql_servers ORDER BY hostgroup_id, hostname;"
WRITERS=$(docker exec dbsec-mysql-1 mysql --ssl-mode=DISABLED -h dbsec-ha-router -P 6032 \
  -uradmin -pradmin -N 2>/dev/null \
  -e "SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=2 AND status='ONLINE';")
if [ "${WRITERS:-0}" = "1" ]; then ok "exactly 1 writer (primary) in hostgroup 2"; else fail "expected 1 writer, found ${WRITERS:-0}"; fi

echo
echo "== 3. Round-trip write/read through the router (port 6450) =="
RT=$(docker exec dbsec-mysql-1 mysql --ssl-mode=DISABLED -h dbsec-ha-router -P 6033 \
  -udbfuser -pdbfpass "${MYSQL_DATABASE:-testdb}" -N 2>/dev/null -e \
  "CREATE TABLE IF NOT EXISTS ha_demo (id INT AUTO_INCREMENT PRIMARY KEY, note VARCHAR(64), ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
   INSERT INTO ha_demo (note) VALUES ('verify-rt');
   SELECT note FROM ha_demo WHERE note='verify-rt' LIMIT 1;")
if [ "$RT" = "verify-rt" ]; then ok "write+read through router succeeded -> $RT"; else fail "round-trip failed (got '$RT')"; fi

echo
echo "== 4. Which node currently serves writes (hostgroup 2 = writer) =="
# Ask the admin directly: with R/W split active, SELECT @@hostname would land on a
# reader and would mislabel the result. runtime_mysql_servers is the source of truth.
SRV=$(docker exec dbsec-mysql-1 mysql --ssl-mode=DISABLED -h dbsec-ha-router -P 6032 \
  -uradmin -pradmin -N 2>/dev/null \
  -e "SELECT hostname FROM runtime_mysql_servers WHERE hostgroup_id=2 AND status='ONLINE' LIMIT 1;")
ok "router currently routes writes to PRIMARY = ${SRV:-unknown}"

echo
echo "HA verification done. Trigger a failover with:"
echo "  python3 scripts/phase7_ha_failover.py"
