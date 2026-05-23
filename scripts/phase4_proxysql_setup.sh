#!/usr/bin/env bash
# Phase 4: load ProxySQL DBF deny rules into the running ProxySQL admin interface.
#
# ProxySQL admin (port 6032) speaks the MySQL protocol. We connect from inside the
# dbsec-mysql container (which has the mysql client) over the docker network and pipe
# in config/proxysql/query_rules.sql.
#
# Run from the project root:
#   bash scripts/phase4_proxysql_setup.sh

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
RULES_FILE="config/proxysql/query_rules.sql"

echo "== Loading ProxySQL query rules from $RULES_FILE =="
# Strip SQL comment lines: ProxySQL's admin parser rejects '--' comments when piped.
grep -v '^[[:space:]]*--' "$RULES_FILE" | docker exec -i dbsec-mysql \
  mysql --ssl-mode=DISABLED -h dbsec-proxysql -P 6032 \
  -u"$ADMIN_USER" -p"$ADMIN_PASS"

echo
echo "== Active query rules now in ProxySQL runtime =="
docker exec dbsec-mysql \
  mysql --ssl-mode=DISABLED -h dbsec-proxysql -P 6032 \
  -u"$ADMIN_USER" -p"$ADMIN_PASS" -t \
  -e "SELECT rule_id, active, match_pattern, error_msg FROM runtime_mysql_query_rules ORDER BY rule_id;"

echo
echo "ProxySQL DBF rules loaded."
