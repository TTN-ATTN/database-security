#!/usr/bin/env bash
# Phase 7.5 (Data Classification) - apply the refactor end-to-end.
#
# Order matters and is non-trivial:
#   1. Apply mysql/phase7_5_classification.sql: widen ssn/cc to VARBINARY, recreate the
#      masked view without ssn/cc, create support/fraud users + RBAC tiers.
#   2. Recreate acra-server with the updated encryptor_config (now covers users.ssn/cc)
#      AND recreate proxysql with the chained config (which carries support/fraud
#      passthrough users). Done as a single `compose ... up -d --force-recreate` so the
#      stack arrives in chained mode in one shot.
#   3. Load Phase 4 DBF deny rules into the freshly recreated ProxySQL.
#   4. Run phase7_5_encrypt_users_pii.py: walks existing rows (which still hold plaintext
#      bytes after the ALTER) and UPDATEs ssn/cc through the chain so Acra encrypts
#      them in place. After this, MySQL stores AcraStruct ciphertext for those columns.
#
# Prereqs: stack is up (base or chained), ACRA_MASTER_KEY in .env (make acra-keys).
#
# Run from the project root:
#   bash scripts/phase7_5_apply.sh

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
set -a; [ -f .env ] && . ./.env; set +a
ROOTPW="${MYSQL_ROOT_PASSWORD:-rootpass}"

if ! grep -q '^ACRA_MASTER_KEY=' .env; then
  echo "ACRA_MASTER_KEY not in .env. Run: make acra-keys" >&2
  exit 1
fi

FILES="-f compose.yaml -f compose.chained.yaml"
PROFILES="--profile acra"

echo "==================== Phase 7.5: Data Classification ===================="

echo
echo "== 1. Apply schema migration (widen columns, rebuild view, add users + RBAC) =="
# Keep stderr visible so a failing GRANT/ALTER/etc. is not silently swallowed.
docker exec -i dbsec-mysql sh -c "exec mysql -uroot -p'$ROOTPW' 2> >(grep -v '\\[Warning\\] Using a password' >&2)" \
    < mysql/phase7_5_classification.sql
echo "  applied mysql/phase7_5_classification.sql"

echo
echo "== 2. Bring stack up in chained mode with new Acra encryptor + ProxySQL users =="
# --force-recreate ensures both services pick up the changed config files (new
# encryptor_config covering users.ssn/cc + new proxysql.chained.cnf with support/fraud).
# shellcheck disable=SC2086
docker compose $FILES $PROFILES up -d --force-recreate acra-server proxysql

echo
echo "== 3. Wait for ProxySQL admin (6032) =="
for i in $(seq 1 30); do
  if docker exec dbsec-mysql mysql --ssl-mode=DISABLED -h dbsec-proxysql -P 6032 \
       -uradmin -pradmin -e "SELECT 1" >/dev/null 2>&1; then echo "  ready"; break; fi
  printf "."; sleep 1
done

echo
echo "== 4. Load DBF deny rules into the recreated ProxySQL =="
bash scripts/phase4_proxysql_setup.sh >/dev/null

echo
echo "== 5. Encrypt existing users.ssn / users.credit_card in place via Acra =="
python3 scripts/phase7_5_encrypt_users_pii.py

echo
echo "Phase 7.5 applied. Verify with:"
echo "  python3 scripts/phase7_5_verify.py"
