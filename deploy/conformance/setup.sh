#!/usr/bin/env bash
# Brings up the engine and registers the two clients the suite needs.
set -euo pipefail
cd "$(dirname "$0")"

: "${IDP_ROOT_KEY:?set IDP_ROOT_KEY -- head -c 32 /dev/urandom | base64}"
export COMPOSE_FILE=../docker-compose.yml

docker compose up -d --build postgres migrate engine
until docker compose exec -T engine /idp verify >/dev/null 2>&1 \
   || curl -sf http://localhost:8099/healthz >/dev/null 2>&1; do sleep 1; done

# The issuer must be the name the SUITE resolves, not the one a human types.
# Relying parties compare it byte-for-byte.
ISSUER="http://idp-engine:8080"

run() { docker compose exec -T engine /idp "$@"; }

run instance create -issuer "$ISSUER" -name conformance

# Both callbacks are registered verbatim. The second carries query parameters on
# purpose: the suite tests that a redirect URI with a query is matched exactly,
# and implementations that normalise or strip it fail.
for n in 1 2; do
  run client create -client-id "conformance-$n" \
      -redirect "https://localhost:8443/test/a/idp/callback" || true
done

echo "clients registered; copy the printed secrets into config.json"
