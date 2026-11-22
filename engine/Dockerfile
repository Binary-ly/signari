# Build stage.
#
# Pinned to a specific Go release, not just the minor: the FIPS module version is
# selected by the toolchain (GOFIPS140), so "whatever go:latest is today" would
# silently change which cryptographic module the binary carries, and the patch
# release is the security floor go.mod declares (the official image builds with
# GOTOOLCHAIN=local, so an older image refuses rather than upgrades).
#
# And to a digest, every base here: a tag is whatever its registry says today,
# and can be pointed somewhere else after the release was checked. The tag stays
# beside it to say what the digest is. docs/deployment-artefacts.md has how to
# move a pin; TestEveryBaseImageIsPinnedByDigest fails on a FROM without one.
FROM golang:1.26.11@sha256:957952ae74dc010608717144399a59a2c6e82ea03d63be1c7ff6577c5a135f93 AS build

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

# The PKCS#11 image, a target of its own: docker build --target pkcs11 .
#
# A PKCS#11 module is a C library the engine loads when it starts, so this binary
# is built with cgo and needs a C library to run on, which the default image has
# none of (docs/signing-keys-in-a-module.md). Built on bookworm to match the
# runtime's: a binary linked against a newer glibc than its image carries does
# not start.
FROM golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS build-pkcs11

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG GOFIPS140=off
ARG SIGNARI_SCHEMA_FINGERPRINT=
ARG SIGNARI_VERSION=
RUN CGO_ENABLED=1 GOFIPS140=${GOFIPS140} \
    go build -trimpath -tags pkcs11 \
      -ldflags="-s -w -X signari.dev/engine/internal/migrate.ExpectedFingerprint=${SIGNARI_SCHEMA_FINGERPRINT} -X main.version=${SIGNARI_VERSION}" \
      -o /out/signari ./cmd/signari

# The module is not in the image. It is the HSM vendor's, mounted when the
# container runs and named by SIGNARI_PKCS11_MODULE. The cc image has glibc and
# the C++ runtime, which a module written in C++, SoftHSM's for one, needs; it
# is still distroless, with no shell or package manager.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS pkcs11

COPY --from=build-pkcs11 /out/signari /signari
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/signari"]
CMD ["serve", "-addr", "0.0.0.0:8080"]

# Runtime stage. The last, so a build that names no target gets this one.
#
# Distroless: no shell, no package manager, no busybox. An attacker who achieves
# execution inside an identity provider should not find a toolchain waiting.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=build /out/signari /signari

# Non-root, the base image's nonroot user. An IdP has no reason to run as root.
#
# By number, not by name: Kubernetes' runAsNonRoot, which the chart sets, can
# only check a number, and refuses to start a container whose image names its
# user. As `nonroot:nonroot` every pod the chart made, the migration Job first,
# stopped at CreateContainerConfigError, so the chart could not install.
USER 65532:65532

EXPOSE 8080

# The engine gates its own startup on the schema VERSION always, and on the schema
# FINGERPRINT: against SIGNARI_SCHEMA_FINGERPRINT when it was supplied at build
# time, and otherwise against the ledger. `signari version` says which this image
# is pinned to, and `signari doctor` what the unpinned case does not catch.
ENTRYPOINT ["/signari"]
CMD ["serve", "-addr", "0.0.0.0:8080"]
