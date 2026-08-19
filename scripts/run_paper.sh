#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="$ROOT_DIR/configs/paper/matrix.csv"
SELECTED=""
RUN_ALL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --scheme) SELECTED="$2"; shift 2 ;;
    --all) RUN_ALL=1; shift ;;
    *) echo "Usage: $0 --scheme NAME | --all" >&2; exit 64 ;;
  esac
done
if [[ $RUN_ALL -eq 0 && -z "$SELECTED" ]]; then echo "Specify --scheme NAME or --all" >&2; exit 64; fi

PARTS=()
FAILED=0
index=0
while IFS=, read -r scheme keyword_num values_per_keyword value_bit_length q; do
  [[ "$scheme" == scheme ]] && continue
  [[ $RUN_ALL -eq 0 && "$scheme" != "$SELECTED" ]] && continue
  part="$ROOT_DIR/results/.paper_${index}_${scheme//-/_}.csv"
  PARTS+=("$part")
  "$ROOT_DIR/scripts/run_experiment.sh" --scheme "$scheme" --keyword-num "$keyword_num" \
    --values-per-keyword "$values_per_keyword" --value-bit-length "$value_bit_length" --q "$q" \
    --timeout "${PAPER_SCHEME_TIMEOUT_SECONDS:-86400}" --output "$part" || FAILED=1
  index=$((index + 1))
done < "$MATRIX"
if [[ ${#PARTS[@]} -eq 0 ]]; then echo "No paper configurations selected." >&2; exit 64; fi
python3 "$ROOT_DIR/scripts/collect_results.py" --output "$ROOT_DIR/results/paper_results.csv" "${PARTS[@]}"
rm -f "${PARTS[@]}"
exit $((FAILED == 0 ? 0 : 2))
