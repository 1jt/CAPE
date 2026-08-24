#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEME=""
KEYWORD_NUM="32"
VALUES_PER_KEYWORD="3"
VALUE_BIT_LENGTH="16"
Q="3"
OUTPUT=""
TIMEOUT_SECONDS="${SCHEME_TIMEOUT_SECONDS:-900}"
JAVA_MAX_HEAP="${JAVA_MAX_HEAP:-2g}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scheme) SCHEME="$2"; shift 2 ;;
    --keyword-num) KEYWORD_NUM="$2"; shift 2 ;;
    --values-per-keyword) VALUES_PER_KEYWORD="$2"; shift 2 ;;
    --value-bit-length) VALUE_BIT_LENGTH="$2"; shift 2 ;;
    --q) Q="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --timeout) TIMEOUT_SECONDS="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 64 ;;
  esac
done

if [[ -z "$SCHEME" ]]; then echo "--scheme is required" >&2; exit 64; fi
if [[ -z "$OUTPUT" ]]; then OUTPUT="$ROOT_DIR/results/${SCHEME//-/_}.csv"; fi
JAR="$ROOT_DIR/mpc4j-s2pc-pir/target/mpc4j-s2pc-pir-1.1.4-alpha-jar-with-dependencies.jar"
NATIVE_DIR="$(find "$ROOT_DIR/mpc4j-native-fhe/build" -type f -name 'libmpc4j-native-fhe.so' -printf '%h\n' -quit 2>/dev/null)"
if [[ ! -f "$JAR" || -z "$NATIVE_DIR" ]]; then
  echo "Artifact is not built. Run ./build.sh first." >&2
  exit 70
fi

mkdir -p "$(dirname "$OUTPUT")" "$ROOT_DIR/results/logs"
LOG_FILE="$ROOT_DIR/results/logs/${SCHEME//-/_}.log"
echo "[INFO] Running $SCHEME (log: ${LOG_FILE#$ROOT_DIR/})"
set +e
LD_LIBRARY_PATH="$NATIVE_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" timeout --signal=TERM "$TIMEOUT_SECONDS" \
  java --add-modules=jdk.incubator.vector -Xmx"$JAVA_MAX_HEAP" -jar "$JAR" \
  --scheme "$SCHEME" --keyword-num "$KEYWORD_NUM" --values-per-keyword "$VALUES_PER_KEYWORD" \
  --value-bit-length "$VALUE_BIT_LENGTH" --q "$Q" --output "$OUTPUT" >"$LOG_FILE" 2>&1
STATUS=$?
set -e
if [[ $STATUS -ne 0 && ! -s "$OUTPUT" ]]; then
  {
    echo "scheme,keyword_num,values_per_keyword,value_bit_length,conjunctive_keyword_num,preprocessing_ms,query_time_ms,query_size_bytes,response_size_bytes,execution_status,correctness_status"
    echo "$SCHEME,$KEYWORD_NUM,$VALUES_PER_KEYWORD,$VALUE_BIT_LENGTH,$Q,-1,-1,-1,-1,FAIL,UNVERIFIED"
  } > "$OUTPUT"
fi
if [[ $STATUS -ne 0 ]]; then
  echo "[WARN] $SCHEME did not complete (exit=$STATUS)." >&2
fi
exit "$STATUS"
