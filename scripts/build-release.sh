#!/usr/bin/env bash
#
# Build a release with the schema fingerprint pinned, and refuse to tag one
# that is not.
#
# A binary built any other way is unpinned: it compares the schema with the
# ledger in the same database, which catches a hand change but not one made
# together with a rewrite of the ledger row. Every image used to be built that
# way, because nothing built one any other way and nothing refused to tag it.
#
# Usage:
#   scripts/build-release.sh [-fips] [-image NAME:TAG] [-tag vX.Y.Z] [output-path]
#
#   -fips    build against Go's CMVP-validated FIPS 140-3 module snapshot
#            (GOFIPS140=certified), and refuse the result unless it reports
#            that module; the image tag gets a -fips suffix. Without it a
#            binary is not built against the validated module at all
#   -image   also build the container image, pinned the same way
#   -tag     create an annotated git tag recording the fingerprint, once the
#            binary (and the image, if built) reports the pin. Refused on a
#            working tree with uncommitted changes, since the tag would name a
#            commit the release was not built from. The tag is not pushed.
#
# The fingerprint comes from scripts/schema-fingerprint.sh, which needs
# SIGNARI_FINGERPRINT_DSN (an empty database) or docker.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="" tag="" out="" fips=off
while [ $# -gt 0 ]; do
    case "$1" in
        -fips)  fips=certified; shift ;;
        -image) image="${2:?-image needs NAME:TAG}"; shift 2 ;;
        -tag)   tag="${2:?-tag needs a version, e.g. v1.2.0}"; shift 2 ;;
        -*)     echo "error: unknown flag $1" >&2; exit 2 ;;
        *)      out="$1"; shift ;;
    esac
done
out="${out:-$here/engine/signari}"
if [ "$fips" != off ] && [ -n "$image" ]; then
    image="${image}-fips"
fi

if [ -n "$tag" ]; then
    if [ -n "$(git -C "$here" status --porcelain)" ]; then
        echo "error: the working tree has uncommitted changes; a release tagged $tag" >&2
        echo "       would name a commit it was not built from. Commit or stash them first." >&2
        exit 1
    fi
    if git -C "$here" rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
        echo "error: tag $tag already exists" >&2
        exit 1
    fi
fi
release="${tag:-$(git -C "$here" describe --tags --always --dirty 2>/dev/null || echo unknown)}"

fp="$("$here/scripts/schema-fingerprint.sh")"
if ! [[ "$fp" =~ ^[0-9a-f]{64}$ ]]; then
    echo "error: the fingerprint is not a 64-character sha256: $fp" >&2
    exit 1
fi

# The pin a built artefact reports, read back from `signari version` rather
# than assumed from the flags it was given.
pin_of() { awk '$1 == "pinned" { print $2 }'; }
# The FIPS module a built artefact reports: "none" unless it was built against
# a snapshot, and only a snapshot is the validated module.
module_of() { awk '$1 == "fips140" { print $NF }'; }
check_fips() {
    if [ "$fips" = off ]; then return; fi
    case "$1" in
        none|"") echo "error: $2 was asked for FIPS and reports no validated module" >&2; exit 1 ;;
    esac
    echo "$2 is built against FIPS module $1" >&2
}

echo "pinning $release to $fp" >&2
cd "$here/engine"
CGO_ENABLED=0 GOFIPS140="$fips" go build -trimpath \
    -ldflags "-s -w -X signari.dev/engine/internal/migrate.ExpectedFingerprint=$fp -X main.version=$release" \
    -o "$out" ./cmd/signari
got="$("$out" version | pin_of)"
if [ "$got" != "$fp" ]; then
    echo "error: $out reports pin '$got', not $fp" >&2
    exit 1
fi
echo "built $out, pinned" >&2
check_fips "$("$out" version | module_of)" "$out"

if [ -n "$image" ]; then
    docker build \
        --build-arg SIGNARI_SCHEMA_FINGERPRINT="$fp" \
        --build-arg SIGNARI_VERSION="$release" \
        --build-arg GOFIPS140="$fips" \
        -t "$image" "$here/engine"
    got="$(docker run --rm "$image" version | pin_of)"
    if [ "$got" != "$fp" ]; then
        echo "error: image $image reports pin '$got', not $fp" >&2
        exit 1
    fi
    echo "built image $image, pinned" >&2
    check_fips "$(docker run --rm "$image" version | module_of)" "image $image"
fi

if [ -n "$tag" ]; then
    git -C "$here" tag -a "$tag" -m "signari $tag" -m "schema fingerprint $fp"
    echo "tagged $tag (not pushed)" >&2
fi
