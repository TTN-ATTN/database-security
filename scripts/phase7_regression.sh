#!/usr/bin/env bash
# Phase 7 - Regression: confirm Phases 1-6 still pass in DEFAULT mode after all the
# Phase 7 additions (override files, HA services, chained scripts).
#
# It first reverts the front ProxySQL to the default direct path (Client -> ProxySQL ->
# MySQL) so the data-plane is back to the Phase 1-6 baseline, then runs every phase
# check and prints a pass/fail summary. HA containers, if running, are left alone (they
# use separate names/ports and do not affect the base stack).
#
# Run from the project root:
#   bash scripts/phase7_regression.sh

set -uo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo "==================== Phase 7: Regression (Phases 1-6) ===================="

echo
echo "== Reverting front ProxySQL to default direct path =="
docker compose up -d --force-recreate proxysql >/dev/null 2>&1 || true
docker compose --profile acra stop acra-server >/dev/null 2>&1 || true
sleep 3

declare -a NAMES=( "Phase 1 (baseline)" "Phase 2 (masking/RBAC)" "Phase 3 (active monitor)" \
                   "Phase 4 (DBF + Acra)" "Phase 5 (perf monitoring)" "Phase 6 (discovery)" )
declare -a CMDS=( "bash scripts/phase1_check.sh" \
                  "bash scripts/phase2_test_masking.sh" \
                  "bash scripts/phase3_check.sh" \
                  "bash scripts/phase4_check.sh" \
                  "bash scripts/phase5_check.sh" \
                  "bash scripts/phase6_check.sh" )

declare -a RESULTS=()
for i in "${!NAMES[@]}"; do
  echo
  echo "──────── ${NAMES[$i]} ────────"
  if eval "${CMDS[$i]}" >/tmp/phase7_reg_$i.log 2>&1; then
    echo -e "  ${GREEN}PASS${NC}  ${NAMES[$i]}"
    RESULTS[$i]="PASS"
  else
    echo -e "  ${RED}FAIL${NC}  ${NAMES[$i]} (tail of log:)"
    tail -8 "/tmp/phase7_reg_$i.log" | sed 's/^/      /'
    RESULTS[$i]="FAIL"
  fi
done

echo
echo "==================== Regression Summary ===================="
fails=0
for i in "${!NAMES[@]}"; do
  if [ "${RESULTS[$i]}" = "PASS" ]; then
    echo -e "  ${GREEN}[PASS]${NC} ${NAMES[$i]}"
  else
    echo -e "  ${RED}[FAIL]${NC} ${NAMES[$i]}  (see /tmp/phase7_reg_$i.log)"
    fails=$((fails+1))
  fi
done
echo
if [ "$fails" -eq 0 ]; then
  echo -e "${GREEN}All Phases 1-6 still pass in default mode.${NC}"
else
  echo -e "${RED}${fails} phase(s) failed regression.${NC}"
  exit 1
fi
