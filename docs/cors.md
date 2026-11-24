# CORS: which endpoints, and the one that must never have it

## Introduction

A page on one website can read an answer from another website only when that
other site allows it. The browser's rule for this is Cross-Origin Resource Sharing
(CORS, see the [glossary](glossary.md#cors)). An application that runs entirely in
the browser needs it to collect tokens from Signari. Such an application is often
called a "single-page application" (SPA).

Signari answers cross-origin requests at the endpoints a browser application
needs, and never at the authorization endpoint. An "origin" is the scheme, host
and port of an address, such as `https://app.example`.

There is no setting to configure. The allowed origins come from each
application's registered redirect URIs.

## The policy

Each endpoint has one of three policies:

| Endpoint | Policy | Why |
|---|---|---|
| `/.well-known/webfinger` | `*` | it answers the same for any account, naming this issuer, so nothing is revealed; a browser client finding its issuer needs it |
| `/.well-known/openid-configuration` | `*` | a client library must read it before it knows any origin |
| `/oauth2/jwks` | `*` | public key material, already world-readable |
| `/oauth2/token` | registered client origin | the request an SPA cannot make without CORS |
| `/oauth2/userinfo` | registered client origin | |
| `/oauth2/revoke`, `/oauth2/introspect` | registered client origin | |
| `/oauth2/par`, `/oauth2/device_authorization` | registered client origin | |
| **`/oauth2/authorize`** | **never** | RFC 9700 §2.6 MUST NOT |
| `/login`, `/device`, `/account`, `/oauth2/logout` | never | browser-facing screens |

In this table, `*` means any origin may read the answer. "Registered client
origin" means only the origins of the application's own redirect URIs may.

## The prohibition, and why it is a test rather than a comment

RFC 9700 §2.6 says:

> CORS **MUST NOT** be supported at the authorization endpoint, as the client
> does not access this endpoint directly; instead, the client redirects the user
> agent to it.

The authorization endpoint is reached by navigation, never by `fetch`. Its
response may already carry an authorization code. So a script that can read it
cross-origin turns a redirect-based flow into a readable one.

The policy is a `switch` whose `corsClientOrigin` case already lists several
`/oauth2/...` paths. The natural way to add the next OAuth endpoint is to widen
that case, which is exactly how the forbidden one would get added. So
`TestTheAuthorizationEndpointNeverGetsCORS` asserts it, and the mutation that
adds `oidc.PathAuthorize` to that case fails it.

## Where the allowed origins come from

Signari allows the origins of the application's own **registered redirect URIs**.
There is nothing else, and no new setting.

Private-use scheme redirects (`com.example.app:/cb`) are skipped. A native
application has no browser origin, so it cannot be the source of a cross-origin
fetch.

The set is cached for a minute. On a database error, the previous answer is served
rather than an empty one. Returning nothing would refuse every SPA at once. And
this list only ever widens what a browser may *read*, never what it may *do*.

## Credentials are never allowed

`Access-Control-Allow-Credentials` is absent from every response, and a test
enforces that it stays absent.

OAuth clients authenticate with a secret or an assertion inside the request, not
with ambient cookies. Signari's session cookie is `__Host-` prefixed and
SameSite=Lax precisely so that it does not travel cross-site.

Setting the credentials flag alongside a reflected origin would undo that, on the
endpoints where it matters most. And it would buy nothing a real application
needs.

The test skips comment lines, because `cors.go` names the header in prose to
record why it is absent. A check that cannot tell an explanation from an
implementation would force the explanation to be deleted.

## Verified against a live server

These requests were made against a live Signari:

| Request | Result |
|---|---|
| Preflight `POST /oauth2/token`, `Origin: https://app.example` (registered) | 204 with `Allow-Origin: https://app.example`, `Allow-Methods`, `Allow-Headers`, `Max-Age`, `Vary: Origin` |
| Same, `Origin: https://evil.example` (not registered) | 204 with **no** CORS headers — the browser refuses the real request |
| Preflight `GET /oauth2/authorize` from a registered origin | 204 with **no** CORS headers |
| `GET /.well-known/openid-configuration` from any origin | `Allow-Origin: *` |

A "preflight" is the request a browser sends first, to ask whether the real
request is allowed.
