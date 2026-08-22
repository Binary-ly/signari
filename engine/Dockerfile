# Build stage.
#
# Pinned to a specific Go minor: the FIPS module version is selected by the
# toolchain (GOFIPS140), so "whatever go:latest is today" would silently change
# which cryptographic module the binary carries.
FROM golang:1.26 AS build

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
# Empty means the drift gate is OFF: migrate.Verify returns before it ever reads
# the live schema, so a container built without this checks the version counter
# and nothing else. The variable's own comment calls that "acceptable during early
# development, never in a release".
#
# It cannot be computed inside `docker build`, because the value is read from a
# live schema and there is no database here. Compute it outside and pass it in:
#
#   docker build --build-arg \
#     SIGNARI_SCHEMA_FINGERPRINT="$(scripts/schema-fingerprint.sh)" .
ARG SIGNARI_SCHEMA_FINGERPRINT=

# CGO off gives a static binary, so the runtime image can be distroless.
# -trimpath keeps build paths out of the binary; they leak directory structure
# and make builds non-reproducible.
RUN CGO_ENABLED=0 GOFIPS140=${GOFIPS140} \
    go build -trimpath \
      -ldflags="-s -w -X signari.dev/engine/internal/migrate.ExpectedFingerprint=${SIGNARI_SCHEMA_FINGERPRINT}" \
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
# FINGERPRINT when SIGNARI_SCHEMA_FINGERPRINT was supplied at build time.
#
# The second half used to be stated unconditionally here and was not true: with no
# pin the fingerprint check returns before reading anything, so an image built
# without the build argument verifies the counter and nothing else. `signari
# doctor` reports which of the two this binary does.
ENTRYPOINT ["/signari"]
CMD ["serve", "-addr", "0.0.0.0:8080"]
