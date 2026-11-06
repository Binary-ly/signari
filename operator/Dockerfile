# The operator: a static binary, run as nobody, nothing else in the image. The build
# image pinned to a digest as engine/Dockerfile's are, and for its reason.
FROM golang:1.26.10@sha256:cfa27959837144bf4649802ba38e59daffd0dd2a7994aa83daaf113285b0f551 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags=-s -o /signari-operator .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /signari-operator /signari-operator
USER 65532:65532
ENTRYPOINT ["/signari-operator"]
