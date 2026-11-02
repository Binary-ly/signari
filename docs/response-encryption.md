# Signed and encrypted responses

TLS protects a response on the wire and ends at whatever terminated it. A client that
needs more can have what this server sends it signed, encrypted to a key of its own, or
both, so that it can be held by something in between without being readable there.

| What | Signed | Encrypted |
|---|---|---|
| ID token | always | `id_token_encrypted_response_alg` |
| Userinfo | `userinfo_signed_response_alg` | `userinfo_encrypted_response_alg` |
| Authorization response | [`authorization_signed_response_alg`](jarm.md) | `authorization_encrypted_response_alg` |
| Introspection | [when asked for](#signed-introspection), with `introspection_signed_response_alg` | `introspection_encrypted_response_alg` |

Each one is the client's choice, and with none set nothing changes.

## Register a key

Encryption needs the client's public key:

```sh
signari client set-keys -client-id app -jwks ./client-jwks.json -keep-auth
```

`-keep-auth` leaves how the client authenticates alone, so one with a secret keeps it.
Without it `client set-keys` moves the client to `private_key_jwt` and removes the
secret. On the client PATCH the same choice is `jwks` with `keep_auth_method`, and in
dynamic registration `jwks` never changes how a client authenticates.

The key has to say it is for this, with `"use": "enc"`, or say nothing. One marked
`"use": "sig"` is never encrypted to, and one marked `"use": "enc"` verifies no
signature. A key with `alg` set is used only for that algorithm.

| `alg` | Key |
|---|---|
| `RSA-OAEP-256` | RSA, 2048 bits or more |
| `ECDH-ES` | EC, on P-256, P-384 or P-521 |

`enc` is `A128CBC-HS256`, which is the default, or `A256CBC-HS512`, `A128GCM` or
`A256GCM`. [Under `fips140=only`](fips.md) the two GCM values are not offered.

RSA1_5 is not offered, because it is an oracle for anybody who can see which ciphertexts
fail. Neither is a key shared with the client: the encrypted token would then say
nothing about which side wrote it.

## Turn it on

```sh
signari client set-encryption -client-id app -for id_token -alg ECDH-ES
signari client set-encryption -client-id app -for userinfo -alg RSA-OAEP-256 -enc A256GCM
signari client set-encryption -client-id app -for authorization -alg ECDH-ES
signari client set-encryption -client-id app -for introspection -alg ECDH-ES
signari client set-encryption -client-id app -for userinfo -alg ""     # off
```

The same settings are `id_token_encrypted_response_alg`, `id_token_encrypted_response_enc`
and their `userinfo_`, `authorization_` and `introspection_` counterparts, on the client PATCH, in `apply`
and in dynamic registration. Discovery lists what is offered as
`id_token_encryption_alg_values_supported` and its counterparts.

It is refused unless the client already holds a key for that algorithm, and a key set
that would leave it without one is refused too.

## What comes back

**An ID token** is signed and then encrypted, a Nested JWT with `cty: JWT`, at the token
endpoint and in a hybrid response. Only the ID token: an access token is for a resource
server, not for the client to open. Decrypt it before using it as an `id_token_hint`,
because this server holds no key to open one with.

**Userinfo** answers `application/jwt` as soon as a client asks for either:

| Signed | Encrypted | Body |
|---|---|---|
| no | no | JSON, as ever |
| yes | no | a JWT, with `iss` and `aud` added |
| no | yes | a JWE holding the JSON |
| yes | yes | a JWE holding the JWT, with `cty: JWT` |

```sh
signari client set-alg -client-id app -userinfo-alg ES256      # -userinfo-alg "" goes back
```

**An authorization response** is [the signed JWT](jarm.md) encrypted to the client, in
the same `response` parameter. Asking for that holds the client to signed responses, as
setting a signing algorithm does. `query.jwt` stays refused for a hybrid response even
encrypted, because a query string is still written down.

## Signed introspection

A resource server that has to show what it was told asks for a JWT (RFC 9701):

```
POST /oauth2/introspect
Accept: application/token-introspection+jwt

token=...&client_assertion=...
```

The answer is `application/token-introspection+jwt`, with that as the JWT's `typ`, and
what RFC 7662 would have said goes under its own claim so that nothing reads it as a
token. There is no `sub` or `exp` at the top level:

```json
{
  "iss": "https://id.example.com",
  "aud": "resource-server",
  "iat": 1793640000,
  "token_introspection": {"active": true, "sub": "...", "scope": "read"}
}
```

A token that is not active gets `{"active": false}` and nothing else. A caller that does
not authenticate gets a 400, not the 401 the JSON form answers, as the RFC requires.

It is signed RS256 unless the client sets another, which RFC 9701 says is the default:

```sh
signari client set-alg -client-id rs -introspection-alg ES256
```

The `Accept` header decides, so a resource server that does not ask gets JSON whatever
is set. Discovery lists `introspection_signing_alg_values_supported` and its encryption
counterparts.

## When it cannot be done

Nothing is sent in the clear instead. The token endpoint, userinfo, introspection and the
authorization endpoint answer a 500, because a client that asked for this has said it
will not take these claims any other way.

## What is not here

**Decrypting anything.** This server holds no encryption key. An encrypted Request
Object is [refused](jar.md#what-is-not-here), and a client cannot encrypt to this server,
so `id_token_hint` and client assertions are signed JWTs.
