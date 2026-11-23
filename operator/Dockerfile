# The operator: a static binary, run as nobody, nothing else in the image. The build
# image pinned to a digest as engine/Dockerfile's are, and for its reason.
FROM golang:1.27.4@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS build
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
