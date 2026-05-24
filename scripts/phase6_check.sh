#!/usr/bin/env bash
# Phase 6 - Sensitive Data Discovery verification.
#
# Runs the two discovery passes and surfaces the key evidence:
#   1. schema scan  -> columns whose NAME looks sensitive (where PII could live)
#   2. data  scan   -> columns whose VALUES match PII patterns (where PII is)
# The headline result is PII leaking into free-text columns that name-based
# masking/RBAC would miss (e.g. activity_logs.notes).
#
# Run from the project root:
#   bash scripts/phase6_check.sh   (or: make phase6)

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${NC} $*"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; }
info() { echo -e "  ${YELLOW}[INFO]${NC} $*"; }

if [ ! -f .env ]; then
  echo "Missing .env. Create it with: cp .env.example .env" >&2
  exit 1
fi

# Use the project venv if present, else system python3 (deps installed globally).
py() { if [ -d .venv ]; then . .venv/bin/activate; fi; python3 "$@"; }

DISCOVERY_DIR="logs/discovery"

echo "==================== Phase 6: Sensitive Data Discovery ===================="

# ── step 1: MySQL reachable ──
echo ""
echo "=== Step 1: MySQL reachable ==="
if docker ps --filter name=dbsec-mysql --format '{{.Names}}' | grep -q dbsec-mysql; then
  ok "dbsec-mysql is running"
else
  fail "dbsec-mysql is not running (start the stack: docker compose up -d)"
  exit 1
fi

# ── step 2: schema scan (name-based) ──
echo ""
echo "=== Step 2: Schema scan (column names) ==="
if py scripts/phase6_scan_schema.py; then
  ok "Schema scan completed"
else
  fail "Schema scan failed"
  exit 1
fi

# ── step 3: data pattern scan (value-based) ──
echo ""
echo "=== Step 3: Data pattern scan (values) ==="
if py scripts/phase6_scan_data_patterns.py --limit 1000 --examples 3; then
  ok "Data pattern scan completed"
else
  fail "Data pattern scan failed"
  exit 1
fi

# ── step 4: confirm evidence artifacts exist ──
echo ""
echo "=== Step 4: Evidence artifacts ==="
for f in schema_findings.json schema_findings.csv data_findings.json data_findings.csv; do
  if [ -s "$DISCOVERY_DIR/$f" ]; then
    ok "$DISCOVERY_DIR/$f"
  else
    fail "missing or empty: $DISCOVERY_DIR/$f"
  fi
done

# ── step 5: masking/RBAC sufficiency (PII reachable by a low-priv account) ──
echo ""
echo "=== Step 5: Exposed PII (low-priv account can read raw - what/where/why) ==="
EXPOSED=$(py -c "
import json
data = json.load(open('$DISCOVERY_DIR/data_findings.json'))
keys = set()
for d in data:
    if d.get('access_verdict') == 'EXPOSED':
        keys.add((d['table'], d['column']))
        vals = ', '.join(d.get('exposed_values') or []) or '(masked - run without --mask-all)'
        print(f\"  - {d['exposed_to']} can SELECT {d['table']}.{d['column']} [{d['pattern_type']}] -> {vals}\")
print(f'TOTAL:{len(keys)}')
" 2>/dev/null || echo "TOTAL:0")
echo "$EXPOSED" | grep -v '^TOTAL:'
EXPOSED_COUNT=$(echo "$EXPOSED" | grep '^TOTAL:' | cut -d: -f2)
if [ "${EXPOSED_COUNT:-0}" -ge 1 ]; then
  info "${EXPOSED_COUNT} table/column(s) expose raw PII to a low-priv account -> add masked view + REVOKE direct SELECT"
else
  ok "No low-priv account can read raw PII directly (masking/RBAC sufficient)"
fi

# ── summary ──
echo ""
echo "=== Phase 6 Summary ==="
ok "Sensitive Data Discovery verification complete."
info "Schema findings : $DISCOVERY_DIR/schema_findings.{json,csv}"
info "Data findings   : $DISCOVERY_DIR/data_findings.{json,csv}"
echo ""
