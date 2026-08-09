#!/usr/bin/env bash
# Executes the conformance plan against the running engine.
set -euo pipefail
cd "$(dirname "$0")"
SUITE="${SUITE_DIR:-$HOME/.cache/idp-conformance}"

[ -f "$SUITE/target/fapi-test-suite.jar" ] || {
  echo "suite jar missing -- build it first:"
  echo "  docker run --rm -v \$SUITE:/src -w /src -v conformance-m2:/root/.m2 \\"
  echo "    maven:3-eclipse-temurin-21 mvn -B clean package -DskipTests"
  exit 1
}

# The suite and the engine must share a network, or the suite cannot resolve
# idp-engine and the issuer check fails before any test runs.
( cd "$SUITE" && docker compose up -d )
docker network connect idp-net conformance-suite-server-1 2>/dev/null || true

python3 "$SUITE/scripts/run-test-plan.py" \
  --show-untested-test-modules \
  "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
  config.json
