# The operator: a static binary, run as nobody, nothing else in the image.
FROM golang:1.26.10 AS build
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
