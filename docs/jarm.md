# Signed authorization responses (JARM)

An authorization code in a URL says nothing about where it came from. With JARM the
whole response is a JWT this server signs, and the client checks it before it reads
any of it.

```
GET /oauth2/authorize?client_id=app&response_type=code&response_mode=jwt&...

HTTP/1.1 303 See Other
Location: https://app.example.com/cb?response=eyJhbGciOiJSUzI1NiIs...
```

| `response_mode` | How the JWT travels |
|---|---|
| `query.jwt` | In the query. Refused for `code id_token`: a signature does not make a query string a place for an assertion |
| `fragment.jwt` | In the fragment |
| `form_post.jwt` | [A page that posts itself](response-modes.md#form_post) |
| `jwt` | The default for the response type: the query for `code`, the fragment for `code id_token` |

`response` is the only parameter. The JWT holds everything else, `state` and `iss`
included, so nothing tempts a client to read a value before checking it:

```json
{
  "iss": "https://id.example.com",
  "aud": "app",
  "exp": 1793640000,
  "code": "PyyFaux2o7Q0YfXBU32jhw",
  "state": "S8NJ7uqk5fY4EjNvP"
}
```

`exp` is five minutes out. `iss` is the issuer the client knows, which is the alias for
a client pinned to one. A hybrid response has `id_token` beside `code`.

A refusal is signed the same way, with `error`, `error_description` and `state` in place
of `code`.

## What a client has to check

In this order, and before it uses anything in the response:

1. The signature, with the key `kid` names in this server's `jwks_uri`. Refuse `none`.
2. `iss` is the server the request was sent to.
3. `aud` is the client's own `client_id`.
4. `exp` has not passed.

Then `state`, as ever.

## Choosing the algorithm

With nothing set a response is signed RS256, which is what JARM says the default is.
Every instance holds an RS256 key from the start.

```sh
signari client set-alg -client-id app -response-alg ES256    # -response-alg "" lets go
```

The same setting is `authorization_signed_response_alg` on the client PATCH, in `apply`,
and in dynamic registration. The algorithms a deployment can sign with are in discovery
as `authorization_signing_alg_values_supported`.

## Holding a client to signed responses

Setting an algorithm does more than choose one. From then on the client gets only
signed responses: a request with any other `response_mode`, or with none, is refused
with `invalid_request`, and that refusal is signed too. Otherwise anybody between the
browser and the client could take the `response_mode` off a request and have the code
sent in the clear.

A walk on [a client's own sign-in page](headless-sign-in.md) ends in the query, so a
client held to signing cannot use one.

## When it cannot be signed

If the instance holds no active key for the algorithm, the answer is a 500 and nothing
reaches the client. The same parameters are never sent unsigned, because a client that
asked for a signature will rightly refuse them, and the code would have crossed a
browser for nothing. `signari doctor` reports a client set to an algorithm with no
active key.

## What is not here

**Encrypted responses.** `authorization_encrypted_response_alg` is not taken. The
signature is what proves where a response came from, and encryption would only hide a
code that PKCE already binds to the client.
