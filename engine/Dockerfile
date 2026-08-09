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

# CGO off gives a static binary, so the runtime image can be distroless.
# -trimpath keeps build paths out of the binary; they leak directory structure
# and make builds non-reproducible.
RUN CGO_ENABLED=0 GOFIPS140=${GOFIPS140} \
    go build -trimpath -ldflags="-s -w" -o /out/idp ./cmd/idp

# Runtime stage.
#
# Distroless: no shell, no package manager, no busybox. An attacker who achieves
# execution inside an identity provider should not find a toolchain waiting.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/idp /idp

# Non-root, from the base image. An IdP has no reason to run as root.
USER nonroot:nonroot

EXPOSE 8080

# The engine gates its own startup on the schema fingerprint, so a container that
# starts at all has already verified it is talking to a database it understands.
ENTRYPOINT ["/idp"]
CMD ["serve", "-addr", "0.0.0.0:8080"]
