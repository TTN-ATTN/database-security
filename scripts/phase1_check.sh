#!/usr/bin/env bash
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

MYSQL_HOST_PORT="${MYSQL_HOST_PORT:-3307}"
MYSQLD_EXPORTER_HOST_PORT="${MYSQLD_EXPORTER_HOST_PORT:-9104}"
PROMETHEUS_HOST_PORT="${PROMETHEUS_HOST_PORT:-9090}"
ALERTMANAGER_HOST_PORT="${ALERTMANAGER_HOST_PORT:-9093}"
GRAFANA_HOST_PORT="${GRAFANA_HOST_PORT:-3000}"

echo "== Docker Compose services =="
docker compose ps

echo
echo "== MySQL connectivity =="
docker exec dbsec-mysql \
  mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" \
  -e "SELECT VERSION() AS mysql_version, CURRENT_USER() AS db_user;"

echo
echo "== Exporter metrics endpoint =="
curl -fsS "http://127.0.0.1:${MYSQLD_EXPORTER_HOST_PORT}/metrics" >/dev/null
echo "mysqld_exporter metrics: ok"

echo
echo "== Prometheus readiness and rules =="
curl -fsS "http://127.0.0.1:${PROMETHEUS_HOST_PORT}/-/ready" >/dev/null
curl -fsS "http://127.0.0.1:${PROMETHEUS_HOST_PORT}/api/v1/rules" >/dev/null
echo "prometheus: ok"

echo
echo "== Alertmanager readiness =="
curl -fsS "http://127.0.0.1:${ALERTMANAGER_HOST_PORT}/-/ready" >/dev/null
echo "alertmanager: ok"

echo
echo "== Grafana health =="
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${GRAFANA_HOST_PORT}/api/health" >/dev/null 2>&1 \
     && curl -fsS -u "${GRAFANA_ADMIN_USER}:${GRAFANA_ADMIN_PASSWORD}" \
          "http://127.0.0.1:${GRAFANA_HOST_PORT}/api/datasources/uid/prometheus" >/dev/null 2>&1 \
     && curl -fsS -u "${GRAFANA_ADMIN_USER}:${GRAFANA_ADMIN_PASSWORD}" \
          "http://127.0.0.1:${GRAFANA_HOST_PORT}/api/dashboards/uid/dbsec-phase1-overview" >/dev/null 2>&1; then
    echo "grafana: ok"
    break
  fi
  [ "$i" = "30" ] && { echo "grafana: FAIL (not ready after 60s)" >&2; exit 1; }
  sleep 2
done

echo
echo "Phase 1 baseline checks passed."
