# Build stage.
#
# Pinned to a specific Go release, not just the minor: the FIPS module version is
# selected by the toolchain (GOFIPS140), so "whatever go:latest is today" would
# silently change which cryptographic module the binary carries, and the patch
# release is the security floor go.mod declares (the official image builds with
# GOTOOLCHAIN=local, so an older image refuses rather than upgrades).
FROM golang:1.26.9 AS build

WORKDIR /src

# Dependencies first, as their own layer: they change far less often than source,
# so an edit to a handler does not re-download the module graph.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# GOFIPS140=certified selects the latest CMVP-VALIDATED module rather than a
# pinned version, so the binary tracks validation as it advances instead of
# freezing on whichever certificate was current the day this was written.
# Set to "off" for a normal build.
ARG GOFIPS140=off

# The schema fingerprint this binary is pinned to.
#
# Empty means unpinned: the engine compares the live schema only with the
# ledger in the same database, which catches a hand change but not one made
# together with a rewrite of the ledger row. Fine for a development image;
# a release is built by scripts/build-release.sh -image, which passes it and
# checks that the image reports it.
#
# It cannot be computed inside `docker build`, because the value is read from a
# live schema and there is no database here. Compute it outside and pass it in:
#
#   docker build --build-arg \
#     SIGNARI_SCHEMA_FINGERPRINT="$(scripts/schema-fingerprint.sh)" .
ARG SIGNARI_SCHEMA_FINGERPRINT=

# The release name `signari version` prints; empty for anything else.
ARG SIGNARI_VERSION=

# CGO off gives a static binary, so the runtime image can be distroless.
# -trimpath keeps build paths out of the binary; they leak directory structure
# and make builds non-reproducible.
RUN CGO_ENABLED=0 GOFIPS140=${GOFIPS140} \
    go build -trimpath \
      -ldflags="-s -w -X signari.dev/engine/internal/migrate.ExpectedFingerprint=${SIGNARI_SCHEMA_FINGERPRINT} -X main.version=${SIGNARI_VERSION}" \
      -o /out/signari ./cmd/signari

# Runtime stage.
#
# Distroless: no shell, no package manager, no busybox. An attacker who achieves
# execution inside an identity provider should not find a toolchain waiting.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/signari /signari

# Non-root, from the base image. An IdP has no reason to run as root.
USER nonroot:nonroot

EXPOSE 8080

# The engine gates its own startup on the schema VERSION always, and on the schema
# FINGERPRINT: against SIGNARI_SCHEMA_FINGERPRINT when it was supplied at build
# time, and otherwise against the ledger. `signari version` says which this image
# is pinned to, and `signari doctor` what the unpinned case does not catch.
ENTRYPOINT ["/signari"]
CMD ["serve", "-addr", "0.0.0.0:8080"]
