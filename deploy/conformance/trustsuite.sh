#!/usr/bin/env bash
# Puts into the suite's running containers what they need to talk to the engine:
# the engine's CA and the suite's own certificate in the JVM's truststore, and that
# certificate in nginx, which is what the engine checks a back-channel logout
# token's destination against.
#
# A container made again has none of it. setup.sh runs this once the clients
# exist, and run.sh runs it again whenever nginx is serving any other certificate,
# because compose can recreate the suite's containers. It did on a GitHub runner,
# before the first plan, and the back-channel plan then waited fifteen minutes for
# a logout token the engine had rightly refused to send to a certificate naming
# nobody.
#
# A JVM reads its truststore once, at startup, so the server is restarted, and
# this waits until it answers again.
set -euo pipefail
cd "$(dirname "$0")"

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

for _ in $(seq 1 90); do
  if curl -ksf https://localhost:8443/api/runner/available >/dev/null; then
    echo "suite restarted with the CA trusted"
    exit 0
  fi
  sleep 2
done
echo "the suite did not answer within three minutes of its restart" >&2
exit 1
