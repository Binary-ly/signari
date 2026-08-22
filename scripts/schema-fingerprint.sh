#!/usr/bin/env bash
#
# Print the schema fingerprint a release binary should be pinned to.
#
# The fingerprint is read from a LIVE schema, not from the migration text, because
# that is what the engine compares against at boot. Deriving it by parsing SQL
# would mean two implementations of "what this schema is", and the one that
# mattered would be the one nobody tested.
#
# So this needs a PostgreSQL to migrate into. It uses whichever is available:
#
#   SIGNARI_FINGERPRINT_DSN   an existing empty database to use, or
#   docker                    a throwaway postgres container it starts and removes
#
# Usage:
#   FP=$(scripts/schema-fingerprint.sh)
#   go build -ldflags "-X signari.dev/engine/internal/migrate.ExpectedFingerprint=$FP" ...
#
# Everything except the digest goes to stderr, so the digest can be captured.
set -euo pipefail

log() { printf '%s\n' "$*" >&2; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here/engine"

# A binary to migrate with. Deliberately built WITHOUT a pin: this one only ever
# talks to the scratch database, and pinning it would need the answer it is being
# used to compute.
tmpbin="$(mktemp -d)/signari-fp"
log "building an unpinned migrator..."
go build -o "$tmpbin" ./cmd/signari

cleanup_container=""
cleanup() {
    if [ -n "$cleanup_container" ]; then
        docker rm -f "$cleanup_container" >/dev/null 2>&1 || true
    fi
    rm -rf "$(dirname "$tmpbin")"
}
trap cleanup EXIT

if [ -n "${SIGNARI_FINGERPRINT_DSN:-}" ]; then
    dsn="$SIGNARI_FINGERPRINT_DSN"
    log "using SIGNARI_FINGERPRINT_DSN"
else
    command -v docker >/dev/null 2>&1 || {
        log "error: no SIGNARI_FINGERPRINT_DSN and no docker."
        log "       The fingerprint is read from a live schema, so one of the two is required."
        exit 1
    }
    cleanup_container="signari-fp-$$"
    port=$(( ( RANDOM % 20000 ) + 30000 ))
    log "starting a throwaway postgres on :$port ..."
    docker run -d --rm --name "$cleanup_container" \
        -e POSTGRES_PASSWORD=fp -e POSTGRES_DB=signari_fp \
        -p "$port:5432" postgres:17-alpine >/dev/null

    dsn="postgres://postgres:fp@127.0.0.1:$port/signari_fp?sslmode=disable"
    log "waiting for it to accept connections..."
    for _ in $(seq 1 60); do
        if docker exec "$cleanup_container" pg_isready -q -U postgres >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
fi

log "applying migrations..."
"$tmpbin" migrate all -dsn "$dsn" >&2

# The digest, and only the digest, on stdout.
"$tmpbin" migrate fingerprint -dsn "$dsn"
