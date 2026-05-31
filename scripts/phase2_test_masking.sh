#!/usr/bin/env bash
# Phase 2: verify data masking and RBAC.
# Run from the project root: bash scripts/phase2_test_masking.sh

set -euo pipefail

CONTAINER="dbsec-mysql"
ROOT_PASS="${MYSQL_ROOT_PASSWORD:-rootpass}"
APP_USER="${MYSQL_APP_USER:-appuser}"
APP_PASS="${MYSQL_APP_PASSWORD:-apppass}"
DB="${MYSQL_DATABASE:-testdb}"

divider() { echo -e "\n========== $1 =========="; }

run_root() { docker exec "$CONTAINER" mysql -uroot -p"$ROOT_PASS" -N -e "$1" "$DB" 2>/dev/null; }
run_app()  { docker exec "$CONTAINER" mysql -u"$APP_USER" -p"$APP_PASS" -N -e "$1" "$DB" 2>/dev/null; }

# NOTE: ssn / credit_card moved to the Phase 7.5 Tier 1 (encrypt-at-rest @ Acra) and
# are no longer projected by users_masked. Tier 1 access is exercised by
# scripts/phase7_5_verify.py (support denied, fraud sees decrypted, DBA sees ciphertext).
# This test focuses on Phase 2's Tier 2 columns (email, phone, address).

divider "1. Root reads raw users table (first 5 rows) - Tier 2 columns"
run_root "SELECT id, email, phone, address FROM users LIMIT 5;"

divider "2. Appuser reads masked view (first 5 rows) - Tier 2 columns"
run_app "SELECT id, email, phone, address FROM users_masked LIMIT 5;"

divider "3. Appuser tries to read raw users table (should FAIL)"
if run_app "SELECT id, email FROM users LIMIT 1;" 2>&1; then
    echo "[FAIL] appuser CAN read raw users table - RBAC misconfigured!"
    exit 1
else
    echo "[PASS] appuser denied access to raw users table"
fi

divider "4. Appuser reads orders (should succeed)"
run_app "SELECT id, user_id, product, amount, status FROM orders LIMIT 5;"
echo "[PASS] appuser can read orders"

divider "5. Appuser reads activity_logs (should succeed)"
run_app "SELECT id, user_id, action, LEFT(notes, 60) AS notes_preview FROM activity_logs LIMIT 5;"
echo "[PASS] appuser can read activity_logs"

divider "6. Appuser tries INSERT on orders (should FAIL)"
if run_app "INSERT INTO orders (user_id, product, amount, status) VALUES (1,'Hack',0,'pending');" 2>&1; then
    echo "[FAIL] appuser CAN insert into orders - RBAC misconfigured!"
    exit 1
else
    echo "[PASS] appuser denied INSERT on orders"
fi

echo ""
echo "All masking and RBAC tests passed."
