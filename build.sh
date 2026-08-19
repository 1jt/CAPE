#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for tool in java javac mvn cmake gcc g++; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Missing required build tool: $tool" >&2
    exit 1
  fi
done

"$ROOT_DIR/scripts/build_native.sh"
mvn -f "$ROOT_DIR/pom.xml" -pl mpc4j-s2pc-pir -am -DskipTests package

JAR="$ROOT_DIR/mpc4j-s2pc-pir/target/mpc4j-s2pc-pir-1.1.4-alpha-jar-with-dependencies.jar"
test -f "$JAR" || { echo "Missing artifact runner JAR: $JAR" >&2; exit 1; }
echo "Build completed successfully."
