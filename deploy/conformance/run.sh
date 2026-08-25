#!/usr/bin/env bash
# Executes a conformance plan against the running engine.
#
#   ./run.sh                 # Basic OP, with the external browser driver
#   ./run.sh config          # Config OP (no browser needed)
#
set -euo pipefail
cd "$(dirname "$0")"
SUITE="${SUITE_DIR:-$HOME/.cache/idp-conformance}"
PLAN="${1:-basic}"

[ -f "$SUITE/target/fapi-test-suite.jar" ] || {
  echo "suite jar missing -- build it first:"
  echo "  docker run --rm -v \$SUITE:/src -w /src -v conformance-m2:/root/.m2 \\"
  echo "    maven:3-eclipse-temurin-21 mvn -B clean package -DskipTests"
  exit 1
}

# The runner's own dependencies. Kept in a virtualenv rather than installed
# globally, because this is a test harness and not something to impose on the
# host's Python.
VENV="${VENV_DIR:-$SUITE/.runner-venv}"
[ -d "$VENV" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q -r "$SUITE/scripts/requirements.txt"

# The suite and the engine must share a network, or the suite cannot resolve
# signari-engine and the issuer check fails before any test runs.
( cd "$SUITE" && docker compose up -d )
docker network connect signari-net idp-conformance-server-1 2>/dev/null || true

# A locally hosted suite has no authentication, so the runner needs dev mode --
# without it, it demands CONFORMANCE_TOKEN and exits before creating a plan.
export CONFORMANCE_SERVER="${CONFORMANCE_SERVER:-https://localhost:8443/}"
export CONFORMANCE_DEV_MODE=1
export DISABLE_SSL_VERIFY=1
export PYTHONWARNINGS=ignore

# --no-parallel is not optional: every module in a plan shares `alias`, so
# parallel modules interrupt each other and most of the plan dies mid-run.
if [ "$PLAN" = "config" ]; then
  # Config OP is pure metadata: no front channel, so no browser driver.
  exec "$VENV/bin/python" "$SUITE/scripts/run-test-plan.py" --no-parallel \
    "oidcc-config-certification-test-plan" config-op.json
fi

# Basic OP needs the front channel driven. The suite's own HtmlUnit driver stalls
# after the callback (see README), so config.json carries no `browser` block and
# browserdrive.py services the URLs the suite publishes instead.
LOG="${LOG:-$(mktemp -t signari-conformance)}"
"$VENV/bin/python" ./browserdrive.py "$LOG" &
DRIVER=$!
trap 'kill $DRIVER 2>/dev/null || true' EXIT

"$VENV/bin/python" "$SUITE/scripts/run-test-plan.py" --no-parallel \
  --show-untested-test-modules \
  "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
  config.json 2>&1 | tee "$LOG"
