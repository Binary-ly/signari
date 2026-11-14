# Quickstart: a Spring Boot application

[examples/spring-quickstart](../examples/spring-quickstart/src/main/java/dev/signari/quickstart/SecurityConfig.java)
signs people in with Signari from a [Spring Boot](https://spring.io/projects/spring-boot)
application, using Spring Security's OAuth 2.0 client.

## 1. Register the application

```sh
signari client create -org <org-id> -client-id quickstart -name Quickstart \
  -redirect http://127.0.0.1:8080/login/oauth2/code/signari
```

It prints the client secret once. Keep it. The redirect URI is Spring's own pattern,
`/login/oauth2/code/<registration>`, matched exactly.

## 2. Run it

```sh
cd examples/spring-quickstart
mvn package
SIGNARI_ISSUER=https://id.example.com CLIENT_ID=quickstart CLIENT_SECRET=<the secret> \
  java -jar target/spring-quickstart-1.0.0.jar
```

Open `http://127.0.0.1:8080/`, follow the link, sign in, and `/me` says who signed in.
Java 17 or later. For a certificate your machine does not trust, import it into a
truststore with `keytool -importcert` and start Java with
`-Djavax.net.ssl.trustStore=<file> -Djavax.net.ssl.trustStorePassword=<password>`.

## What it does, and the two settings Signari needs

`application.properties` names Signari by `issuer-uri`. Spring reads the discovery
document at start and refuses one naming another issuer. The registration uses
`client_secret_basic`, scopes `openid email profile`, and Spring's redirect pattern.

`SecurityConfig` adds the two things Spring does not assume:

1. **PKCE for a confidential client.** Signari requires it of every client and
   accepts only `S256`. Spring adds it by itself only for public clients, so the
   authorization request resolver is given `OAuth2AuthorizationRequestCustomizers.withPkce()`.
2. **The ID token's algorithm.** Spring checks the ID token's signature against the
   published keys, then its issuer, audience, expiry and nonce. It expects RS256
   unless told otherwise, and Signari signs with ES256 by default. The
   `OidcIdTokenDecoderFactory` bean names ES256. A client set to another algorithm
   with `signari client set-alg` names that one there instead.

A public client has no secret: leave `CLIENT_SECRET` unset, set `CLIENT_AUTH=none`, and
register it with `-public`. A refused sign-in sends the browser to Spring's
`/login?error`; the engine's own message is in its log and in
[troubleshooting.md](troubleshooting.md).

## Verified

On 14 November 2026, with Java 17, Maven 3.9.16, Spring Boot 4.1.2 and Spring Security
7.1.2, against a running engine over TLS. Ada signed in through the engine's pages and
`/me` said "Signed in as ada@staff.test". The engine's access log showed `/oauth2/jwks`
fetched for the signature. With the ES256 line taken out, the same sign-in was refused
and the browser was sent back to Spring's login page. A callback this browser never
began went to `/login?error`, and `/me` signed out sent the browser to sign in.
