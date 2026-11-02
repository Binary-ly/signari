# Signed authorization requests (JAR)

RFC 9101. An authorization request is ordinarily a URL, which anybody holding the
browser can read and change. A client that signs its request sends a JWT instead, and
what reaches this server is what the client asked for.

```
GET /oauth2/authorize?client_id=app&request=eyJhbGciOiJFUzI1NiIs...
```

The JWT's claims are the request's parameters, and nothing else in the URL counts:
§6.3 says only the parameters in the Request Object are used, even where the same one
is in the query, so a `scope` added to the URL is ignored. `client_id` has to be in
both, and the same.

```json
{
  "iss": "app",
  "aud": "https://id.example.com",
  "client_id": "app",
  "exp": 1793500000,
  "response_type": "code",
  "scope": "openid profile",
  "redirect_uri": "https://app.example.com/cb",
  "state": "af0ifjsldkj",
  "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "code_challenge_method": "S256"
}
```

Register the public key first, with `signari client set-keys -client-id app -jwks
keys.json`, and sign with RS, PS or ES at 256, 384 or 512, or EdDSA. What this server
takes is in discovery, as `request_object_signing_alg_values_supported`.

## What is checked

| | |
|---|---|
| The signature | By a key this client registered. With a `kid`, that key and no other |
| The algorithm | Nothing symmetric, and not `none`: §10.1 needs it signed, and a shared secret does not say which party signed |
| `client_id` | The same as the request's |
| `iss` | This client. Required here, where §4 says SHOULD |
| `aud` | This server's issuer. Required here too, or an object signed for another server would be good at this one |
| `exp` | Not passed, and within 60 minutes of `nbf` or of now. May be left out, as the RFC allows |
| `nbf` | Passed |
| `request`, `request_uri` | Not inside: §4 forbids it |

Anything short of all that is `invalid_request_object`, sent to the `redirect_uri` in
the query if it is one this client registered. With none in the query, and a client that
signs usually has none, there is nowhere checked to send it, so it is shown on a page
here. It is never an authorization that carries on without the object.

## In a push

A request object can be pushed, which is what FAPI 2.0 Message Signing asks for and
gives the most: signed, and never through a browser at all.

```
POST /oauth2/par
client_id=app&client_assertion=...&request=eyJhbGciOiJFUzI1NiIs...
```

## Requiring it

Until a client has to sign, the signature is something an attacker leaves off. That is
the downgrade §10.5 describes:

```sh
signari client set-signed-requests -client-id app      # -require-signed=false lifts it
```

Then its unsigned requests are refused, at `/oauth2/authorize` and at `/oauth2/par`. The
same switch is `require_signed_request_object` on the client PATCH, in `apply`, and in
dynamic registration, where it is RFC 9101's name.

A request object sent by value does not satisfy `require_pushed_authorization`: it came
through the browser, which is what a push keeps it from doing.

## How it travels

Once verified, a request object is parked as a pushed request is, and the pages after it
carry a handle. Spread over a URL it would be open to whoever holds the browser, the
moment the signature had been checked. So a person who takes a while over a sign-in does
not run into an `exp` of a minute, and the handle lives as a pushed request's does, five
minutes. See [par.md](par.md).

Each one is a row, so it is paced as a push is: a captured URL can be sent again.

## What is not here

**`request_uri` is a pushed request's handle and nothing else.** This server does not
fetch a Request Object from a URL a client names, which is an address somebody else
chose for it to connect to, so `request_uri_parameter_supported` is `false`.

**An encrypted Request Object is refused.** Signing is what gives the integrity. Encryption
would keep the parameters from the browser, which a push does already.
