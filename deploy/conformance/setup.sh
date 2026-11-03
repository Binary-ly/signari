#!/usr/bin/env bash
# Brings up the engine over TLS and registers what the conformance suite needs.
#
# Every value below was corrected against an actual suite run on 25 August 2026.
# The previous version of this script could not pass a single module, for four
# separate reasons, none of which produced an obvious error:
#
#  1. the issuer was http://, so seven Config OP conditions failed on
#     CheckDiscEndpointAllEndpointsAreHttps and the rest never ran
#  2. the redirect URI was https://localhost:8443/..., but the suite's own
#     base_url is https://localhost.emobix.co.uk:8443 (set in its
#     docker-compose.yml). Every Basic OP module died on
#     "redirect_uri is not registered for this client"
#  3. the loop registered the SAME uri twice, so the query-parameter variant the
#     comment described was never registered at all
#  4. clients default to require_pkce, and the OIDC Basic profile sends no
#     challenge, so every authorization request was refused with
#     "code_challenge is required"
#
set -euo pipefail
cd "$(dirname "$0")"

: "${SIGNARI_ROOT_KEY:?set SIGNARI_ROOT_KEY -- head -c 32 /dev/urandom | base64}"
export COMPOSE_FILE=../docker-compose.yml

# The issuer must be HTTPS and must be the name the SUITE resolves, not the one a
# human types. Relying parties compare it byte-for-byte, and OIDC requires https
# for the issuer and every endpoint derived from it.
ISSUER="https://signari-engine:8080"
SUITE_BASE="https://localhost.emobix.co.uk:8443"
CALLBACK="$SUITE_BASE/test/a/signari/callback"

# TLS, because the issuer above is https. The SAN must carry signari-engine --
# the compose network alias -- or the suite rejects the certificate before any
# test runs.
if [ ! -f ../tls/engine.crt ] ||
   ! openssl x509 -in ../tls/engine.crt -noout -text | grep -q 'DNS:signari-engine'; then
  echo "generating a TLS certificate for signari-engine"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout ../tls/ca.key -out ../tls/ca.crt -subj "/CN=signari-conformance-ca" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout ../tls/engine.key -out ../tls/engine.csr \
    -subj "/CN=signari-engine" 2>/dev/null
  openssl x509 -req -in ../tls/engine.csr -CA ../tls/ca.crt -CAkey ../tls/ca.key \
    -CAcreateserial -out ../tls/engine.crt -days 3650 \
    -extfile ../tls/san.cnf -extensions ext 2>/dev/null
  rm -f ../tls/engine.csr ../tls/ca.srl
fi
export SIGNARI_TLS_CERT=/tls/engine.crt
export SIGNARI_TLS_KEY=/tls/engine.key

# For the back-channel logout plan the engine posts logout tokens to the suite, and its
# outbound guard is right to refuse both halves of that: the suite's nginx serves a
# self-signed certificate for CN=localhost with no SAN, on a private address. So the
# nginx is given a certificate naming the host the suite calls itself by, and the
# engine trusts that one certificate and may reach this compose network, and nothing
# else is loosened.
if [ ! -f ../tls/suite.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout ../tls/suite.key -out ../tls/suite.crt -subj "/CN=localhost.emobix.co.uk" \
    -addext "subjectAltName=DNS:localhost.emobix.co.uk,DNS:localhost" 2>/dev/null
fi
export SIGNARI_CA_BUNDLE=/tls/suite.crt

# Order matters and used to be wrong: the engine refuses to start until an
# instance exists, so `up -d engine` before `instance create` leaves a container
# restarting forever while the wait loop spins.
# The engine image must be REBUILT, not just started. Skipping this is a quiet
# failure: the container keeps whatever binary it was last built with, so a flag
# added since -- `-require-pkce`, for one -- is "not defined" and the run dies
# somewhere unrelated to the actual cause.
docker compose build engine
docker compose up -d postgres
until [ "$(docker inspect -f '{{.State.Health.Status}}' signari-postgres-1)" = healthy ]; do
  sleep 1
done
SIGNARI_OUTBOUND_ALLOW_PRIVATE="$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' signari-net)"
export SIGNARI_OUTBOUND_ALLOW_PRIVATE
docker compose up migrate

# `run` before the engine is up needs a one-off container, not exec. Bootstrap and not
# `instance create`, which makes no organisation for the clients below to belong to.
docker compose run --rm --no-deps engine bootstrap -issuer "$ISSUER" -email admin@test.local

docker compose up -d engine
until curl -ksf "https://localhost:8099/.well-known/openid-configuration" >/dev/null; do sleep 1; done

run() { docker compose exec -T engine /signari "$@"; }

# -require-pkce=false is deliberate and is scoped to these two clients. The OIDC
# Basic profile predates the rule that PKCE is mandatory and sends no challenge,
# so a client that demands one cannot complete a single module of that plan. It
# is a property of the profile being certified, not a weakening of the default:
# every other client still gets require_pkce = true.
for n in 1 2; do
  run client create -client-id "conformance-$n" -redirect "$CALLBACK" -require-pkce=false
done

# A THIRD client, for client_secret_post.
#
# oidcc-server-client-secret-post declares `client_secret_post.client_id` and
# `.client_secret` as required configuration fields and its configureClient()
# does `config.add("client", config.get("client_secret_post"))`. With that block
# absent the substitution puts null in `client`, and the module dies on
# GetStaticClientConfiguration -- "the test configuration must contain a client
# configuration" -- while the logged config plainly contains one, because the
# copy happens before the check.
#
# The suite asks for a separate client rather than reusing the first because
# most servers restrict a client to a single authentication method.
run client create -client-id "conformance-post" -redirect "$CALLBACK" -require-pkce=false

# FAPI 2.0 (./run.sh fapi2): two clients authenticating with private_key_jwt, their
# tokens bound by DPoP, their requests pushed, and held to the profile, which refuses
# that last step until the rest is so. PKCE stays required, as the profile has it.
# The private keys stay in ../tls, which git ignores; fapiconfig.py puts them in a
# configuration for the suite.
node fapikeys.mjs ../tls
for n in 1 2; do
  c="conformance-fapi-$n"
  docker cp "../tls/fapi$n.public.json" "signari-engine-1:/tmp/fapi$n.public.json"
  run client create -client-id "$c" -name "FAPI $n" -redirect "$CALLBACK"
  run client set-keys -client-id "$c" -jwks "/tmp/fapi$n.public.json"
  run client set-dpop -client-id "$c" -dpop-bound
  run client set-par -client-id "$c" -require-par
  run client set-profile -client-id "$c" -security-profile fapi2
  # And the same for FAPI 2.0 Message Signing (./run.sh fapi2-ms), with the same key:
  # requests signed, responses signed with ES256 as JARM, held to that profile.
  m="conformance-fapims-$n"
  run client create -client-id "$m" -name "FAPI MS $n" -redirect "$CALLBACK"
  run client set-keys -client-id "$m" -jwks "/tmp/fapi$n.public.json"
  run client set-dpop -client-id "$m" -dpop-bound
  run client set-par -client-id "$m" -require-par
  run client set-signed-requests -client-id "$m"
  run client set-alg -client-id "$m" -response-alg ES256
  run client set-profile -client-id "$m" -security-profile fapi2-message-signing
done

# The second callback carries query parameters on purpose: the suite tests that a
# redirect URI with a query is matched exactly, and implementations that
# normalise or strip it fail. `client create` registers one URI, and there is no
# verb for adding another, so this goes in directly -- and bumps config_version,
# because ADR-008 is what tells a running engine to reload.
docker compose exec -T postgres psql -U signari_superuser -d signari -v ON_ERROR_STOP=1 <<SQL
INSERT INTO core.client_redirect_uris (client_id, redirect_uri) VALUES
 ('conformance-1', '$CALLBACK?dummy1=lorem&dummy2=ipsum'),
 ('conformance-2', '$CALLBACK?dummy1=lorem&dummy2=ipsum'),
 ('conformance-fapi-1', '$CALLBACK?dummy1=lorem&dummy2=ipsum'),
 ('conformance-fapi-2', '$CALLBACK?dummy1=lorem&dummy2=ipsum'),
 ('conformance-fapims-1', '$CALLBACK?dummy1=lorem&dummy2=ipsum'),
 ('conformance-fapims-2', '$CALLBACK?dummy1=lorem&dummy2=ipsum')
ON CONFLICT DO NOTHING;
UPDATE core.config_version SET version = version + 1 WHERE id = true;
SQL

# `code id_token` is off for a client until someone turns it on and says when to look
# at it again, and `code token` and `code id_token token` stay refused whatever is set
# here: an access token does not cross the front channel. So the Hybrid plan's modules
# for those two fail on purpose; see the README.
for c in conformance-1 conformance-2 conformance-post; do
  run client set-hybrid -client-id "$c" -review-by 2031-01-01
done

# The password must not contain the username: the engine's own policy refuses
# "conformance-password-1" for a user named conformance@test.local, which is the
# control working as intended and not a bug to route around.
run user create -email conformance@test.local -password 'Tr0ubad0ur-Marmalade-7719'

# The suite is a JVM and will not trust our CA until it is in the truststore AND
# the process has restarted -- a JVM reads it once, at startup.
if docker ps --format '{{.Names}}' | grep -q '^idp-conformance-server-1$'; then
  docker cp ../tls/ca.crt idp-conformance-server-1:/tmp/signari-ca.crt
  docker cp ../tls/suite.crt idp-conformance-server-1:/tmp/signari-suite.crt
  docker exec -u 0 idp-conformance-server-1 sh -c \
    'keytool -importcert -noprompt -trustcacerts -alias signari-conformance \
       -file /tmp/signari-ca.crt -cacerts -storepass changeit;
     keytool -importcert -noprompt -trustcacerts -alias signari-suite \
       -file /tmp/signari-suite.crt -cacerts -storepass changeit' >/dev/null 2>&1 || true
  docker cp ../tls/suite.crt idp-conformance-nginx-1:/etc/ssl/certs/nginx-selfsigned.crt
  docker cp ../tls/suite.key idp-conformance-nginx-1:/etc/ssl/private/nginx-selfsigned.key
  docker exec idp-conformance-nginx-1 nginx -s reload >/dev/null 2>&1
  docker restart idp-conformance-server-1 >/dev/null
  docker network connect signari-net idp-conformance-server-1 2>/dev/null || true
  # The name the suite gives itself, so a logout token posted to it arrives.
  docker network connect --alias localhost.emobix.co.uk signari-net idp-conformance-nginx-1 2>/dev/null || true
  echo "suite restarted with the CA trusted"
fi

echo
echo "clients registered; copy the printed secrets into config.json"
echo "issuer:   $ISSUER"
echo "callback: $CALLBACK"
