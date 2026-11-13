# The quickstart as the demo application of deploy/docker-compose.yml's `demo` profile
# (6.21). Standard library only, so a build fetches nothing but the two images, which are
# the engine's and pinned by digest as its are (TestEveryBaseImageIsPinnedByDigest).
FROM golang:1.26.10@sha256:cfa27959837144bf4649802ba38e59daffd0dd2a7994aa83daaf113285b0f551 AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/quickstart .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/quickstart /quickstart
# By number, as the engine's image is, so runAsNonRoot can check it.
USER 65532:65532
ENTRYPOINT ["/quickstart"]
