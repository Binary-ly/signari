#!/bin/bash
# The database machine of a scale run: PostgreSQL 17 alone, the schema at head, an instance whose
# issuer is the nodes' balancer, a client and 1,000 people to sign in as in its organisation, and
# seed.sql's million. Remote connections need TLS and a scram-sha-256 password, and come only
# from ALLOW. Run as root on a Debian or Ubuntu machine you can throw away.
#
#   ALLOW=<nodes' address>/32 PGDATA_DIR=/dev/shm/pg ./database.sh
#
# Writes OUT (default ./scale-out): engine-pw, root-key, client-secret and person-pw, which the
# nodes need, each readable by root alone. Needs `signari` and `bench` on PATH.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
: "${ALLOW:?give ALLOW, the address the nodes connect from, as a /32}"
PGDATA_DIR=${PGDATA_DIR:-/var/lib/postgresql/17/main}
OUT=${OUT:-$PWD/scale-out}
mkdir -p "$OUT" && chmod 700 "$OUT"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
apt-get install -yq curl ca-certificates postgresql-common openssl >/dev/null
/usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y >/dev/null 2>&1
apt-get install -yq postgresql-17 >/dev/null
pg_dropcluster 17 main --stop 2>/dev/null || true
mkdir -p "$(dirname "$PGDATA_DIR")" && chown postgres:postgres "$(dirname "$PGDATA_DIR")"
pg_createcluster 17 main -d "$PGDATA_DIR" > /dev/null
C=/etc/postgresql/17/main
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=scale-db -days 3 -keyout $C/server.key -out $C/server.crt 2>/dev/null
chown postgres:postgres $C/server.key $C/server.crt && chmod 600 $C/server.key
cat > $C/pg_hba.conf <<EOF
local all all trust
host all all 127.0.0.1/32 trust
hostssl signari signari_engine $ALLOW scram-sha-256
EOF
cat >> $C/postgresql.conf <<EOF
listen_addresses = '*'
ssl = on
ssl_cert_file = '$C/server.crt'
ssl_key_file = '$C/server.key'
password_encryption = scram-sha-256
max_connections = 400
shared_buffers = 4GB
effective_cache_size = 12GB
EOF
pg_ctlcluster 17 main start

D=signari
psql -q -U postgres -h 127.0.0.1 -c "CREATE DATABASE $D"
SIGNARI_DSN=postgres://postgres@127.0.0.1/$D signari migrate bootstrap > /dev/null
SIGNARI_DSN=postgres://signari_engine@127.0.0.1/$D signari migrate up > /dev/null
head -c 32 /dev/urandom | base64 > "$OUT/root-key" && chmod 600 "$OUT/root-key"
export SIGNARI_ROOT_KEY_FILE=$OUT/root-key SIGNARI_DSN=postgres://signari_engine@127.0.0.1/$D SIGNARI_INSECURE_ISSUER=1
ORG=$(signari bootstrap -issuer http://127.0.0.1:8080 -email owner@bench.invalid | awk '/^organisation/ {print $2}')
head -c 18 /dev/urandom | base64 | tr -d '/+=' > "$OUT/person-pw" && chmod 600 "$OUT/person-pw"
signari user create -org "$ORG" -email template@bench.invalid -password "$(cat "$OUT/person-pw")" > /dev/null
signari user create -org "$ORG" -email signin@bench.invalid -password "$(cat "$OUT/person-pw")" > /dev/null
bench seed -dsn "$SIGNARI_DSN" -org "$ORG" -template template@bench.invalid -users 1000
psql -U postgres -h 127.0.0.1 $D -f "$here/seed.sql"
signari client create -org "$ORG" -client-id bench -name Bench -redirect https://bench.invalid/cb |
	awk '/client_secret/ {print $2}' > "$OUT/client-secret" && chmod 600 "$OUT/client-secret"
signari client set-grants -client-id bench -grant-types authorization_code,refresh_token,client_credentials > /dev/null
# The defaults (6,000 tokens and 1,200 sign-ins a minute) are a tenant's share, and a run spends
# the sign-in budget in seconds; raised to the most they take, and the write-up says so.
signari instance org-budgets -org "$ORG" -tokens-per-minute 1000000 -sign-ins-per-minute 1000000 > /dev/null
head -c 24 /dev/urandom | base64 | tr -d '/+=' > "$OUT/engine-pw" && chmod 600 "$OUT/engine-pw"
psql -q -U postgres -h 127.0.0.1 -c "ALTER ROLE signari_engine PASSWORD '$(cat "$OUT/engine-pw")'"
echo "ready: copy $OUT to the nodes' machine"
