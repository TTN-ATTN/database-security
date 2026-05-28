#!/usr/bin/env bash
# Phase 7 - Revert from CHAINED mode back to the default direct path:
#   Client -> ProxySQL (DBF) -> MySQL    (Acra back to optional / stopped)
#
# Run from the project root:
#   bash scripts/phase7_chain_down.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "== Recreating ProxySQL with the default backend (dbsec-mysql:3306) =="
# Bringing the stack up WITHOUT compose.chained.yaml restores the default ProxySQL
# config + command. --force-recreate is required because compose otherwise keeps the
# running container as-is when the spec hasn't changed; we want the previous chained
# command/volume gone.
docker compose up -d --force-recreate proxysql

echo
echo "== Stopping acra-server (it was in the chained path; default stack doesn't need it) =="
# Acra is profile-gated in the base compose.yaml; without --profile acra it is not part
# of the project. Stop it explicitly so it doesn't keep running idle.
docker compose --profile acra stop acra-server || true

echo
echo "== Verifying ProxySQL backend points at MySQL =="
docker exec dbsec-mysql mysql --ssl-mode=DISABLED -h dbsec-proxysql -P 6032 \
  -uradmin -pradmin -t 2>/dev/null \
  -e "SELECT hostgroup_id, hostname, port FROM runtime_mysql_servers;"

echo
echo "Default mode is active. Phase 1-6 scripts work as before."
