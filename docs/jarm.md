# Signed authorization responses (JARM)

## Introduction

At the end of a sign-in, Signari sends the browser back to the application with an
authorization code in the URL. That code says nothing about where it came from.
Instead, the whole response can be a JSON Web Token (JWT) that Signari signs.

That is "JWT-Secured Authorization Response Mode" (JARM), and the application
checks the response before it reads any of it (see the
[glossary](glossary.md#jarm)).

An application asks for it with a `response_mode`. You can hold one application to
signed responses by choosing its algorithm with `signari client set-alg`.

## How it works

The application asks for a signed response, and Signari answers with one
`response` parameter:

```
GET /oauth2/authorize?client_id=app&response_type=code&response_mode=jwt&...

HTTP/1.1 303 See Other
Location: https://app.example.com/cb?response=eyJhbGciOiJSUzI1NiIs...
```

The `response_mode` decides how the JWT travels:

| `response_mode` | How the JWT travels |
|---|---|
| `query.jwt` | In the query. Refused for `code id_token`: a signature does not make a query string a place for an assertion |
| `fragment.jwt` | In the fragment |
| `form_post.jwt` | [A page that posts itself](response-modes.md#form_post) |
| `jwt` | The default for the response type: the query for `code`, the fragment for `code id_token` |

`response` is the only parameter. The JWT holds everything else, `state` and `iss`
included, so nothing tempts an application to read a value before checking it:

```json
{
  "iss": "https://id.example.com",
  "aud": "app",
  "exp": 1793640000,
  "code": "PyyFaux2o7Q0YfXBU32jhw",
  "state": "S8NJ7uqk5fY4EjNvP"
}
```

`exp` is five minutes out. `iss` is the issuer the application knows, which is the
alias for an application pinned to one. A hybrid response has `id_token` beside
`code`.

A refusal is signed the same way, with `error`, `error_description` and `state` in
place of `code`.

## What a client has to check

The application checks these in this order, before it uses anything in the
response:

1. The signature, with the key `kid` names in Signari's `jwks_uri`. Refuse `none`.
2. `iss` names the identity provider the request was sent to.
3. `aud` is the application's own `client_id`.
4. `exp` has not passed.

Then it checks `state`, as ever.

## Choosing the algorithm

With nothing set, a response is signed RS256 (RSA with SHA-256), which is what
JARM says the default is. Every instance holds an RS256 key from the start (see [key
rotation](key-rotation.md)).

To sign one application's responses with ES256 (ECDSA with SHA-256) instead, run:

```sh
signari client set-alg -client-id app -response-alg ES256    # -response-alg "" lets go
```

The same setting is `authorization_signed_response_alg` on the client PATCH, in
`apply`, and in dynamic registration. The algorithms a deployment can sign with are
in its discovery document, as `authorization_signing_alg_values_supported`.

## Holding a client to signed responses

Setting an algorithm does more than choose one. From then on, the application gets
only signed responses. A request with any other `response_mode`, or with none, is
refused with `invalid_request`, and that refusal is signed too.

Otherwise anybody between the browser and the application could take the
`response_mode` off a request. They could then have the code sent in the clear.

A sign-in through [an application's own sign-in page](headless-sign-in.md) ends in
the query. So an application held to signing cannot use one.

## When it cannot be signed

If the instance holds no active key for the algorithm, the answer is a 500, and
nothing reaches the application. The same parameters are never sent unsigned. An
application that asked for a signature will rightly refuse them, and the code
would have crossed a browser for nothing.

`signari doctor` reports an application set to an algorithm with no active key.

## Encrypting it

An application can have the signed response [encrypted to a key of its
own](response-encryption.md) as well. That holds it to signed responses in the
same way.
