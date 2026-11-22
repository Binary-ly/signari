# The Spring Boot quickstart as a demo application of deploy/docker-compose.yml's `demo`
# profile, at http://localhost:8094/. Built with Maven against pom.xml's Spring Boot
# 4.1.2, run on Java 17; both bases pinned by digest, as every image here is
# (TestEveryBaseImageIsPinnedByDigest).
FROM maven:3.9-eclipse-temurin-26-noble@sha256:b2c1ad85954592f9928e84327c65201f308ad9b5d8ed7d5b823717c97bf23fbb AS build
WORKDIR /src
COPY pom.xml ./
COPY src ./src
RUN mvn -B -q package

FROM eclipse-temurin:17.0.21_9-jre-noble@sha256:042c05a77eb915684fc8c92cfbbef4fd6f8c24ca7d934d1a7db3543453aaa077
COPY --from=build /src/target/spring-quickstart-1.0.0.jar /app/quickstart.jar
# Java does not read a PEM file as a truststore. With SIGNARI_CA_FILE set, as the demo
# sets it to the development CA, each start imports that one certificate into a
# truststore of its own under a password made then and never shown, and Java trusts
# only it. Unset, Java trusts its own store.
COPY --chmod=0755 <<'EOF' /usr/local/bin/quickstart
#!/bin/sh
set -eu
if [ -n "${SIGNARI_CA_FILE:-}" ]; then
  pass=$(head -c 24 /dev/urandom | base64)
  # A restarted container keeps /tmp, and keytool refuses an alias it already holds.
  rm -f /tmp/truststore.p12
  keytool -importcert -noprompt -alias signari-ca -file "$SIGNARI_CA_FILE" \
    -keystore /tmp/truststore.p12 -storetype PKCS12 -storepass "$pass" >/dev/null
  set -- -Djavax.net.ssl.trustStore=/tmp/truststore.p12 -Djavax.net.ssl.trustStorePassword="$pass"
fi
exec java "$@" -jar /app/quickstart.jar
EOF
# The image's own `ubuntu` user, by number, so runAsNonRoot can check it.
USER 1000:1000
CMD ["/usr/local/bin/quickstart"]
