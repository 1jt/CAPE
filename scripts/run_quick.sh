#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$ROOT_DIR/configs/quick/quick.conf"
source "$CONFIG"
SCHEMES=(MMK BKPIR FusePIR FusePIR-C CAPE CAPE-C)
PARTS=()
FAILED=0
rm -f "$ROOT_DIR/results/quick_results.csv"
mkdir -p "$ROOT_DIR/results/logs"

for scheme in "${SCHEMES[@]}"; do
  part="$ROOT_DIR/results/.quick_${scheme//-/_}.csv"
  PARTS+=("$part")
  q_value="$q"
  if [[ "$scheme" == MMK || "$scheme" == FusePIR || "$scheme" == FusePIR-C ]]; then q_value=1; fi
  "$ROOT_DIR/scripts/run_experiment.sh" --scheme "$scheme" --keyword-num "$keyword_num" \
    --values-per-keyword "$values_per_keyword" --value-bit-length "$value_bit_length" --q "$q_value" \
    --timeout "$scheme_timeout_seconds" --output "$part" || FAILED=1
done

python3 "$ROOT_DIR/scripts/collect_results.py" --output "$ROOT_DIR/results/quick_results.csv" "${PARTS[@]}"
rm -f "${PARTS[@]}"
if [[ $FAILED -ne 0 ]]; then
  echo "Some schemes did not complete successfully."
  echo "See results/quick_results.csv and docs/CORRECTNESS_STATUS.md."
  exit 2
fi
echo "Quick experiment completed: results/quick_results.csv"
