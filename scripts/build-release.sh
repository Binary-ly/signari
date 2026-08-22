#!/usr/bin/env bash
#
# Build a release binary with the schema fingerprint pinned.
#
# An unpinned binary skips the drift gate entirely: migrate.Verify returns before
# it ever reads the live schema, so the check the Dockerfile advertises does not
# run. That is acceptable during development and, in the variable's own words,
# "never in a release".
#
# Usage: scripts/build-release.sh [output-path]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$here/engine/signari}"

fp="$("$here/scripts/schema-fingerprint.sh")"
if [ ${#fp} -ne 64 ]; then
    echo "error: the fingerprint is ${#fp} characters, expected a 64-character sha256" >&2
    echo "got: $fp" >&2
    exit 1
fi

echo "pinning to $fp" >&2
cd "$here/engine"
CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X signari.dev/engine/internal/migrate.ExpectedFingerprint=$fp" \
    -o "$out" ./cmd/signari
echo "built $out" >&2
