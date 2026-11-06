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
# SIGNARI_FINGERPRINT_DSN (an empty database) or docker. govulncheck and gosec
# must be on PATH: a release is refused on a reachable vulnerability or a
# finding above engine/gosec-baseline.txt, and is built twice and refused
# unless the two binaries are byte-identical. cyclonedx-gomod must be too: each
# binary gets a CycloneDX SBOM beside it, <output>.cdx.json, and the image's its
# own, <output>.image.cdx.json, since the binary in the image is built for another
# platform.
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

# The release gate: a reachable vulnerability, or a static-analysis finding
# above the reviewed baseline, refuses the release, as CI refuses a push. A
# release built on a workstation never passed through CI.
for tool in govulncheck gosec cyclonedx-gomod jq; do
    if ! command -v "$tool" >/dev/null; then
        echo "error: $tool is not on PATH; a release is not built unscanned or undescribed" >&2
        echo "       (go install golang.org/x/vuln/cmd/govulncheck@v1.7.0," >&2
        echo "        github.com/securego/gosec/v2/cmd/gosec@v2.28.0 and" >&2
        echo "        github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0)" >&2
        exit 1
    fi
done

# The SBOM of a built binary: CycloneDX, read from the build information the binary
# carries, so it lists what was linked and not what go.mod would allow, with each
# module's hash. The standard library is in it, whose advisories are as much the
# release's as any module's. No serial number or timestamp, so it is as repeatable
# as the binary. Refused when it does not list every module the binary names, or
# names another platform: the tool takes GOOS and GOARCH from the environment and
# not the binary, so the image's linux build was first described as darwin's.
sbom_of() {
    local goos goarch want got std
    goos="$(go version -m "$1" | awk '$1 == "build" && $2 ~ /^GOOS=/ { sub("GOOS=", "", $2); print $2 }')"
    goarch="$(go version -m "$1" | awk '$1 == "build" && $2 ~ /^GOARCH=/ { sub("GOARCH=", "", $2); print $2 }')"
    GOOS="$goos" GOARCH="$goarch" cyclonedx-gomod bin -json -std -noserial -notimestamp -version "$release" \
        -output "$2" "$1" 2>/dev/null
    want="$(go version -m "$1" | awk '$1 == "dep"' | wc -l | tr -d ' ')"
    got="$(jq '[.components[] | select(.name != "std")] | length' "$2")"
    std="$(jq -r '.components[] | select(.name == "std") | .purl' "$2")"
    if [ "$got" != "$want" ] || [ -z "$std" ]; then
        echo "error: the SBOM $2 lists $got modules and the binary names $want, or it leaves out the standard library" >&2
        exit 1
    fi
    case "$std" in
        *"goarch=$goarch"*"goos=$goos"*) ;;
        *) echo "error: the SBOM $2 describes $std, and the binary is $goos/$goarch" >&2; exit 1 ;;
    esac
    echo "SBOM $2: $got modules and the standard library, for $goos/$goarch" >&2
}
if ! (cd "$here/engine" && govulncheck ./...) >&2; then
    echo "error: govulncheck reports a reachable vulnerability; not building $release" >&2
    exit 1
fi
if ! "$here/scripts/gosec-check.sh" >&2; then
    echo "error: gosec reports findings above the reviewed baseline; not building $release" >&2
    exit 1
fi

echo "pinning $release to $fp" >&2
cd "$here/engine"
build() {
    CGO_ENABLED=0 GOFIPS140="$fips" go build -trimpath \
        -ldflags "-s -w -X signari.dev/engine/internal/migrate.ExpectedFingerprint=$fp -X main.version=$release" \
        -o "$1" ./cmd/signari
}
build "$out"
# Built twice and compared, so the claim that a release can be rebuilt from its
# tag is checked here rather than assumed.
again="$(mktemp)"
build "$again"
if ! cmp -s "$out" "$again"; then
    rm -f "$again"
    echo "error: two builds of $release are not byte-identical; it could not be rebuilt and checked" >&2
    exit 1
fi
rm -f "$again"
echo "two builds are byte-identical: sha256 $(shasum -a 256 "$out" | cut -c1-64)" >&2
got="$("$out" version | pin_of)"
if [ "$got" != "$fp" ]; then
    echo "error: $out reports pin '$got', not $fp" >&2
    exit 1
fi
echo "built $out, pinned" >&2
check_fips "$("$out" version | module_of)" "$out"
sbom_of "$out" "$out.cdx.json"

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
    # The image's binary is another platform's build, so it is described from
    # itself: copied out, never run.
    inside="$(mktemp -d)"
    container="$(docker create "$image")"
    docker cp "$container:/signari" "$inside/signari" >/dev/null
    docker rm "$container" >/dev/null
    sbom_of "$inside/signari" "$out.image.cdx.json"
    rm -rf "$inside"
fi

if [ -n "$tag" ]; then
    git -C "$here" tag -a "$tag" -m "signari $tag" -m "schema fingerprint $fp"
    echo "tagged $tag (not pushed)" >&2
fi
