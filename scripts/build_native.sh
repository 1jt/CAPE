#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NATIVE_DIR="$ROOT_DIR/mpc4j-native-fhe"
BUILD_DIR="$NATIVE_DIR/build"

if [[ -z "${JAVA_HOME:-}" ]]; then
  JAVA_BIN="$(readlink -f "$(command -v java)")"
  export JAVA_HOME="$(dirname "$(dirname "$JAVA_BIN")")"
fi

cmake -S "$NATIVE_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" --parallel "${BUILD_JOBS:-2}"

NATIVE_LIBRARY="$(find "$BUILD_DIR" -type f -name 'libmpc4j-native-fhe.so' -print -quit)"
if [[ -z "$NATIVE_LIBRARY" ]]; then
  echo "Native build did not produce libmpc4j-native-fhe.so" >&2
  exit 1
fi
echo "$NATIVE_LIBRARY"
