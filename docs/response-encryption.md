# Signed and encrypted responses

## Introduction

Transport Layer Security (TLS) protects a response on the wire, and its protection
ends at whatever terminated it (see the [glossary](glossary.md#tls)). Some
applications need more than that.

Such an application can have what Signari sends it signed, encrypted to a key of
its own, or both. Then the response can be held by something in between without
being readable there.

Each one is the application's choice, and with none set nothing changes. You turn
encryption on with `signari client set-encryption`, and choose a signing algorithm
with `signari client set-alg`.

## What can be signed and encrypted

Each kind of response has its own settings:

| What | Signed | Encrypted |
|---|---|---|
| ID token | always | `id_token_encrypted_response_alg` |
| Userinfo | `userinfo_signed_response_alg` | `userinfo_encrypted_response_alg` |
| Authorization response | [`authorization_signed_response_alg`](jarm.md) | `authorization_encrypted_response_alg` |
| Introspection | [when asked for](#signed-introspection), with `introspection_signed_response_alg` | `introspection_encrypted_response_alg` |

## Register a key

Encryption needs the application's public key. To register it without changing
how the application authenticates, run:

```sh
signari client set-keys -client-id app -jwks ./client-jwks.json -keep-auth
```

`-keep-auth` leaves how the application authenticates alone, so one with a secret
keeps it. Without it, `client set-keys` moves the application to `private_key_jwt`
and removes the secret (see [client authentication](client-authentication.md)).

On the client PATCH, the same choice is `jwks` with `keep_auth_method`. In dynamic
registration, `jwks` never changes how an application authenticates.

The key has to say it is for this, with `"use": "enc"`, or say nothing. One marked
`"use": "sig"` is never encrypted to, and one marked `"use": "enc"` verifies no
signature. A key with `alg` set is used only for that algorithm.

The key must suit the algorithm:

| `alg` | Key |
|---|---|
| `RSA-OAEP-256` | RSA, 2048 bits or more |
| `ECDH-ES` | EC, on P-256, P-384 or P-521 |

`enc` is `A128CBC-HS256`, which is the default, or `A256CBC-HS512`, `A128GCM` or
`A256GCM`. [Under `fips140=only`](fips.md) the two GCM values are not offered.

RSA1_5 is not offered, because it is an oracle for anybody who can see which
ciphertexts fail. Neither is a key shared with the application: the encrypted token
would then say nothing about which side wrote it.

## Turn it on

To encrypt each kind of response, or to turn one off again, run:

```sh
signari client set-encryption -client-id app -for id_token -alg ECDH-ES
signari client set-encryption -client-id app -for userinfo -alg RSA-OAEP-256 -enc A256GCM
signari client set-encryption -client-id app -for authorization -alg ECDH-ES
signari client set-encryption -client-id app -for introspection -alg ECDH-ES
signari client set-encryption -client-id app -for userinfo -alg ""     # off
```

The same settings are `id_token_encrypted_response_alg`, `id_token_encrypted_response_enc`
and their `userinfo_`, `authorization_` and `introspection_` counterparts. You can set
them on the client PATCH, in `apply` and in dynamic registration. The discovery
document lists what is offered, as `id_token_encryption_alg_values_supported` and
its counterparts.

It is refused unless the application already holds a key for that algorithm. A key
set that would leave it without one is refused too.

## What comes back

**An ID token** is signed and then encrypted, at the token endpoint and in a hybrid
response. That makes it a signed JSON Web Token (JWT) inside an encrypted one,
which the standard calls a "Nested JWT", with `cty: JWT`.

Only the ID token is encrypted. An access token is for a "resource server", the
protocol's word for an API that accepts tokens, and not for the application to
open. Decrypt the ID token before using it as an `id_token_hint`, because Signari
holds no key to open one with.

**Userinfo** answers `application/jwt` as soon as an application asks for either:

| Signed | Encrypted | Body |
|---|---|---|
| no | no | JSON, as ever |
| yes | no | a JWT, with `iss` and `aud` added |
| no | yes | a JWE holding the JSON |
| yes | yes | a JWE holding the JWT, with `cty: JWT` |

In this table, a JWE (JSON Web Encryption) object is the encrypted form. To sign
userinfo responses, run:

```sh
signari client set-alg -client-id app -userinfo-alg ES256      # -userinfo-alg "" goes back
```

**An authorization response** is [the signed JWT](jarm.md) encrypted to the
application, in the same `response` parameter. Asking for that holds the
application to signed responses, as setting a signing algorithm does. `query.jwt`
stays refused for a hybrid response even encrypted, because a query string is
still written down.

## Signed introspection

"Introspection" is a resource server asking Signari whether a token is still valid
(see the [glossary](glossary.md#introspection)). A resource server that has to
show what it was told asks for a JWT (RFC 9701):

```
POST /oauth2/introspect
Accept: application/token-introspection+jwt

token=...&client_assertion=...
```

The answer is `application/token-introspection+jwt`, with that as the JWT's
`typ`. What RFC 7662 would have said goes under its own claim, so that nothing
reads it as a token. There is no `sub` or `exp` at the top level:

```json
{
  "iss": "https://id.example.com",
  "aud": "resource-server",
  "iat": 1793640000,
  "token_introspection": {"active": true, "sub": "...", "scope": "read"}
}
```

A token that is not active gets `{"active": false}` and nothing else. A caller that
does not authenticate gets a 400, not the 401 the JSON form answers, as the RFC
requires.

It is signed RS256 (RSA with SHA-256) unless the application sets another, which
RFC 9701 says is the default. To sign with ES256 (ECDSA with SHA-256) instead, run:

```sh
signari client set-alg -client-id rs -introspection-alg ES256
```

The `Accept` header decides, so a resource server that does not ask gets JSON
whatever is set. The discovery document lists
`introspection_signing_alg_values_supported` and its encryption counterparts.

## When it cannot be done

Nothing is sent in the clear instead. The token endpoint, userinfo, introspection
and the authorization endpoint answer a 500. An application that asked for this has
said it will not take these claims any other way.

## What is not here

**Encrypting to Signari, for an application.** An encrypted Request Object is
[refused](jar.md#what-is-not-here), and `id_token_hint` and client assertions are
signed JWTs. The one message that arrives encrypted is a wallet's
[credential request](oid4vci.md#a-credential-only-the-wallet-can-read), to a key
that exists for that and nothing else.
