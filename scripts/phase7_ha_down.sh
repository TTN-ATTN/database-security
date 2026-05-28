#!/usr/bin/env bash
# Phase 7 - Tear down the HA cluster + GR router.
#
# Stops and removes the 3 MySQL nodes, the ProxySQL HA router, AND their data volumes
# (the cluster is meant to be re-bootstrapped from scratch each time). The base
# single-node stack (mysql, proxysql, prometheus, grafana, ...) is left untouched.
#
#   bash scripts/phase7_ha_down.sh

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "== Stopping & removing HA containers =="
docker rm -f dbsec-mysql-1 dbsec-mysql-2 dbsec-mysql-3 dbsec-ha-router 2>/dev/null || true

echo
echo "== Removing HA data volumes =="
docker volume rm \
  database-security_mysql_ha_1_data \
  database-security_mysql_ha_2_data \
  database-security_mysql_ha_3_data 2>/dev/null || true

echo
echo "HA stack removed. Base single-node stack is unaffected."
echo "Re-create with: bash scripts/phase7_ha_bootstrap.sh"
