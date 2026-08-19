#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
find "$ROOT_DIR" -mindepth 2 -maxdepth 2 -type d -name target -prune -exec rm -rf -- {} +
rm -rf -- "$ROOT_DIR/mpc4j-native-fhe/build"
rm -f -- "$ROOT_DIR/results/quick_results.csv" "$ROOT_DIR/results/paper_results.csv"
rm -rf -- "$ROOT_DIR/results/logs"
mkdir -p "$ROOT_DIR/results/logs"
echo "Artifact build outputs removed."
