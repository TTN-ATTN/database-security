#!/usr/bin/env bash
# One-off helper: strip CRLF from text config files committed from Windows.
set -e
cd "$(dirname "$0")/.."

targets=(
  .env .env.example .gitignore Makefile requirements.txt
  mysql/init.sql mysql/schema.sql mysql/masking.sql mysql/rbac.sql mysql/my.cnf
  config/prometheus/prometheus.yml
  config/alertmanager/alertmanager.yml
  config/mysqld-exporter/.my.cnf
)

# Also include rules and grafana provisioning trees if present.
shopt -s nullglob
for f in config/prometheus/rules/*.yml \
         config/grafana/provisioning/datasources/*.yml \
         config/grafana/provisioning/dashboards/*.yml \
         config/grafana/dashboards/*.json; do
  targets+=("$f")
done

for f in "${targets[@]}"; do
  if [ -f "$f" ] && file "$f" | grep -q CRLF; then
    sed -i 's/\r$//' "$f"
    echo "fixed: $f"
  fi
done

echo "done."
