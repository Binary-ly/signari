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
# Somewhere other than the tracked template, so a secret is not one `git add` away.
# Split, because the runner's grammar takes a relative name and reads an absolute
# path as the name of a plan.
CONFIG="${CONFIG:-config.json}"
CONFIG_DIR="$(cd "$(dirname "$CONFIG")" && pwd)"
CONFIG_FILE="$(basename "$CONFIG")"

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
"$VENV/bin/pip" install -q -r "$SUITE/scripts/requirements.txt" requests

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

docker network connect --alias localhost.emobix.co.uk signari-net idp-conformance-nginx-1 2>/dev/null || true

# Each logout plan wants the clients to have its channel and no other: a front-channel
# URI registered while the RP-initiated plan runs is a request that plan "wasn't
# expecting", and fails it.
CB="https://localhost.emobix.co.uk:8443/test/a/signari"
logout() {
  for c in conformance-1 conformance-2; do
    docker exec signari-engine-1 /signari client set-logout -client-id "$c" \
      -post-logout-redirects "$CB/post_logout_redirect" -frontchannel-uri "$1" -backchannel-uri "$2" >/dev/null
  done
}

STATIC="[server_metadata=discovery][client_registration=static_client]"
LOGOUT="[response_type=code][client_registration=static_client]"
case "$PLAN" in
  basic)     SPEC="oidcc-basic-certification-test-plan$STATIC" ;;
  formpost)  SPEC="oidcc-formpost-basic-certification-test-plan$STATIC" ;;
  hybrid)    SPEC="oidcc-hybrid-certification-test-plan$STATIC" ;;
  rp-logout) logout "" ""; SPEC="oidcc-rp-initiated-logout-certification-test-plan$LOGOUT" ;;
  fc-logout) logout "$CB/frontchannel_logout" ""; SPEC="oidcc-frontchannel-rp-initiated-logout-certification-test-plan$LOGOUT" ;;
  bc-logout) logout "" "$CB/backchannel_logout"; SPEC="oidcc-backchannel-rp-initiated-logout-certification-test-plan$LOGOUT" ;;
  # CONFIG from fapiconfig.py, which carries the two FAPI clients' private keys.
  fapi2)     SPEC="fapi2-security-profile-final-test-plan[openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi]" ;;
  fapi2-mtls) SPEC="fapi2-security-profile-final-test-plan[openid=openid_connect][client_auth_type=mtls][sender_constrain=mtls][fapi_profile=plain_fapi]" ;;
  fapi2-ms)  SPEC="fapi2-message-signing-final-test-plan[openid=openid_connect][client_auth_type=private_key_jwt][fapi_request_method=signed_non_repudiation][sender_constrain=dpop][fapi_profile=plain_fapi][fapi_response_mode=jarm]" ;;
  # An offer this server mints, delivered by the driver, redeemed as a pre-authorized code.
  vci-offer)
    ORG="$(docker exec signari-postgres-1 psql -U signari_superuser -d signari -At \
      -c "SELECT id FROM core.organizations ORDER BY created_at LIMIT 1")"
    export CONFORMANCE_OFFER_CMD="docker exec signari-engine-1 /signari credential offer -org $ORG \
      -email conformance@test.local -client-id conformance-fapi-1 -credential-configuration IdentityCredential \
      -credential-issuer https://signari-engine:8080 -tx-code"
    SPEC="oid4vci-1_0-issuer-test-plan[authorization_request_type=simple][client_auth_type=private_key_jwt][fapi_request_method=unsigned][sender_constrain=dpop][fapi_profile=vci][credential_format=sd_jwt_vc][vci_credential_encryption=plain][openid=plain_oauth][fapi_response_mode=plain_response][vci_grant_type=pre_authorization_code][vci_authorization_code_flow_variant=issuer_initiated]" ;;
  # rar, not simple: the configuration names no scope, so the suite asks by details.
  vci)       SPEC="oid4vci-1_0-issuer-test-plan[authorization_request_type=rar][client_auth_type=private_key_jwt][fapi_request_method=unsigned][sender_constrain=dpop][fapi_profile=vci][credential_format=sd_jwt_vc][vci_credential_encryption=plain][openid=plain_oauth][fapi_response_mode=plain_response][vci_grant_type=authorization_code][vci_authorization_code_flow_variant=wallet_initiated]" ;;
  # This server as an OID4VP verifier, the suite as the wallet; CONFIG from
  # fapiconfig.py --vp. The driver starts each sign-in here and hands the suite the
  # wallet URL's query, as a person's phone would open it.
  # By the engine's own name, which browserdrive.py rewrites as it does every other
  # visit: requests files a cookie under the Host header, so the cookie set here is the
  # one the browser takes back when the wallet returns it there.
  vp)        export CONFORMANCE_VP_START="https://signari-engine:8080/oid4vp/vp/start"
             SPEC="oid4vp-1final-verifier-test-plan[credential_format=sd_jwt_vc][client_id_prefix=x509_san_dns][request_method=request_uri_signed][response_mode=direct_post][vp_profile=plain_vp]" ;;
  vp-plain)  export CONFORMANCE_VP_START="https://signari-engine:8080/oid4vp/vp-plain/start"
             SPEC="oid4vp-1final-verifier-test-plan[credential_format=sd_jwt_vc][client_id_prefix=redirect_uri][request_method=url_query][response_mode=direct_post][vp_profile=plain_vp]" ;;
  *)         SPEC="$PLAN" ;; # any other plan, with its variants, as the runner takes it
esac

# Everything else needs the front channel driven. The suite's own HtmlUnit driver
# stalls after the callback (see README), so config.json carries no `browser` block
# and browserdrive.py services the URLs the suite publishes instead.
LOG="${LOG:-$(mktemp -t signari-conformance)}"
"$VENV/bin/python" ./browserdrive.py "$LOG" &
DRIVER=$!
trap 'kill $DRIVER 2>/dev/null || true' EXIT

( cd "$CONFIG_DIR" && "$VENV/bin/python" "$SUITE/scripts/run-test-plan.py" --no-parallel \
  "$SPEC" "$CONFIG_FILE" ) 2>&1 | tee "$LOG"
