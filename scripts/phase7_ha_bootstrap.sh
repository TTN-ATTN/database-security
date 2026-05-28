#!/usr/bin/env bash
# Phase 7 - Bootstrap a 3-node MySQL Group Replication cluster (manual, via SQL) and a
# ProxySQL GR-aware router in front of it.
#
# Why manual GR (not MySQL Shell / InnoDB Cluster): the MySQL Shell image is not
# publicly pullable, and MySQL Router needs Shell-created metadata. Manual GR uses only
# the mysql client already in the mysql:8.4 image, and ProxySQL (image we have) provides
# the failover-aware routing. See compose.ha.yaml for the rationale.
#
# Steps:
#   1. Start the 3 nodes, wait until healthy.
#   2. On each node: clear the entrypoint-generated GTIDs (RESET), create the GR
#      recovery user without logging it, point the recovery channel at it.
#   3. Bootstrap the group on node-1, then start GR on node-2 and node-3.
#   4. Wait for all 3 members ONLINE.
#   5. Apply the project schema/users to the primary (replicates to secondaries).
#   6. Start the ProxySQL GR router and confirm it tracks the primary.
#
# Run from the project root:
#   bash scripts/phase7_ha_bootstrap.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

set -a; [ -f .env ] && . ./.env; set +a
ROOTPW="${MYSQL_ROOT_PASSWORD:-rootpass}"
DB="${MYSQL_DATABASE:-testdb}"

COMPOSE="docker compose -f compose.yaml -f compose.ha.yaml --profile ha"
NODES=(dbsec-mysql-1 dbsec-mysql-2 dbsec-mysql-3)

# Run SQL on a node as root (local socket).
sql() { local node="$1"; shift; docker exec -i "$node" mysql -uroot -p"$ROOTPW" -N -e "$*" 2>/dev/null; }

echo "==================== Phase 7: HA Cluster Bootstrap ===================="

echo
echo "== 1. Start 3 nodes and wait for healthy =="
$COMPOSE up -d mysql-1 mysql-2 mysql-3
for n in "${NODES[@]}"; do
  printf "  %s " "$n"
  for i in $(seq 1 60); do
    st=$(docker inspect -f '{{.State.Health.Status}}' "$n" 2>/dev/null || echo missing)
    [ "$st" = "healthy" ] && { echo "healthy"; break; }
    printf "."; sleep 3
    [ "$i" = "60" ] && { echo " TIMEOUT"; exit 1; }
  done
done

echo
echo "== 2. Prepare each node for Group Replication =="
for n in "${NODES[@]}"; do
  echo "  $n: reset GTIDs, create recovery user, set recovery channel"
  # Clear GTIDs the docker-entrypoint generated (root@%, etc.) so all nodes start from
  # an empty, identical GTID set. Create the recovery user WITHOUT binlog so it does
  # not introduce a new errant transaction.
  sql "$n" "
    RESET BINARY LOGS AND GTIDS;
    SET SQL_LOG_BIN=0;
    CREATE USER IF NOT EXISTS 'repl'@'%' IDENTIFIED WITH mysql_native_password BY 'replpass';
    GRANT REPLICATION SLAVE, BACKUP_ADMIN, GROUP_REPLICATION_STREAM ON *.* TO 'repl'@'%';
    FLUSH PRIVILEGES;
    SET SQL_LOG_BIN=1;
    CHANGE REPLICATION SOURCE TO SOURCE_USER='repl', SOURCE_PASSWORD='replpass'
      FOR CHANNEL 'group_replication_recovery';
  "
done

echo
echo "== 3. Bootstrap the group on node-1, then join node-2 and node-3 =="
sql dbsec-mysql-1 "
  SET GLOBAL group_replication_bootstrap_group=ON;
  START GROUP_REPLICATION;
  SET GLOBAL group_replication_bootstrap_group=OFF;
"
sleep 3
sql dbsec-mysql-2 "START GROUP_REPLICATION;"
sql dbsec-mysql-3 "START GROUP_REPLICATION;"

echo
echo "== 4. Wait for all 3 members ONLINE =="
for i in $(seq 1 40); do
  online=$(sql dbsec-mysql-1 "SELECT COUNT(*) FROM performance_schema.replication_group_members WHERE MEMBER_STATE='ONLINE';" || echo 0)
  if [ "${online:-0}" = "3" ]; then echo "  3/3 ONLINE"; break; fi
  printf "  %s/3 online ...\r" "${online:-0}"; sleep 3
  [ "$i" = "40" ] && { echo; echo "  TIMEOUT waiting for ONLINE members"; sql dbsec-mysql-1 "SELECT MEMBER_HOST,MEMBER_STATE FROM performance_schema.replication_group_members;"; exit 1; }
done
sql dbsec-mysql-1 "SELECT MEMBER_HOST AS host, MEMBER_STATE AS state, MEMBER_ROLE AS role FROM performance_schema.replication_group_members ORDER BY MEMBER_HOST;"

echo
echo "== 5. Apply project schema/users to the primary (replicates to secondaries) =="
PRIMARY=$(sql dbsec-mysql-1 "SELECT MEMBER_HOST FROM performance_schema.replication_group_members WHERE MEMBER_ROLE='PRIMARY';")
echo "  primary = ${PRIMARY:-dbsec-mysql-1}"
applyp() { docker exec -i "${PRIMARY:-dbsec-mysql-1}" mysql -uroot -p"$ROOTPW" 2>/dev/null "$@"; }
applyp -e "CREATE DATABASE IF NOT EXISTS ${DB};
           CREATE USER IF NOT EXISTS 'appuser'@'%' IDENTIFIED BY '${MYSQL_APP_PASSWORD:-apppass}';
           GRANT SELECT ON ${DB}.* TO 'appuser'@'%'; FLUSH PRIVILEGES;"
for f in schema masking rbac proxysql-users phase4_encryption_demo; do
  echo "  applying mysql/${f}.sql"
  applyp < "mysql/${f}.sql" || echo "    (warning: ${f}.sql reported an error, continuing)"
done
applyp < mysql/init.sql || true
# ProxySQL's GR monitor needs to read replication_group_members on each node.
applyp -e "GRANT SELECT ON performance_schema.* TO 'monitor'@'%'; FLUSH PRIVILEGES;"
echo "  schema + grants applied"

echo
echo "== 6. Start the ProxySQL GR router and confirm primary tracking =="
$COMPOSE up -d ha-router
echo "  waiting for ha-router admin (6452) ..."
for i in $(seq 1 30); do
  if docker exec dbsec-mysql-1 mysql --ssl-mode=DISABLED -h dbsec-ha-router -P 6032 \
       -uradmin -pradmin -e "SELECT 1" >/dev/null 2>&1; then echo "  admin ready"; break; fi
  printf "."; sleep 2
done
sleep 5  # let the GR monitor classify writer/reader hostgroups
echo
echo "  ProxySQL runtime hostgroups (HG2=writer, HG3=reader):"
docker exec dbsec-mysql-1 mysql --ssl-mode=DISABLED -h dbsec-ha-router -P 6032 \
  -uradmin -pradmin -t 2>/dev/null \
  -e "SELECT hostgroup_id, hostname, status FROM runtime_mysql_servers ORDER BY hostgroup_id;"

echo
echo "HA cluster + GR router ready."
echo "  Verify : bash scripts/phase7_ha_verify.sh"
echo "  Failover demo : python3 scripts/phase7_ha_failover.py"
