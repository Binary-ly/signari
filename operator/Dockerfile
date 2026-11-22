# The operator: a static binary, run as nobody, nothing else in the image. The build
# image pinned to a digest as engine/Dockerfile's are, and for its reason.
FROM golang:1.26.11@sha256:957952ae74dc010608717144399a59a2c6e82ea03d63be1c7ff6577c5a135f93 AS build
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
