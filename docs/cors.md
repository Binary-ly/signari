# CORS: which endpoints, and the one that must never have it


## The policy

| Endpoint | Policy | Why |
|---|---|---|
| `/.well-known/openid-configuration` | `*` | a client library must read it before it knows any origin |
| `/oauth2/jwks` | `*` | public key material, already world-readable |
| `/oauth2/token` | registered client origin | the request an SPA cannot make without CORS |
| `/oauth2/userinfo` | registered client origin | |
| `/oauth2/revoke`, `/oauth2/introspect` | registered client origin | |
| `/oauth2/par`, `/oauth2/device_authorization` | registered client origin | |
| **`/oauth2/authorize`** | **never** | RFC 9700 §2.6 MUST NOT |
| `/login`, `/device`, `/account`, `/oauth2/logout` | never | browser-facing screens |

## The prohibition, and why it is a test rather than a comment

RFC 9700 §2.6:

> CORS **MUST NOT** be supported at the authorization endpoint, as the client
> does not access this endpoint directly; instead, the client redirects the user
> agent to it.

The authorization endpoint is reached by navigation, never by `fetch`. Its
response may already carry an authorization code, so a script that can read it
cross-origin turns a redirect-based flow into a readable one.

The policy is a `switch` whose `corsClientOrigin` case already lists several
`/oauth2/...` paths. The natural way to add the next OAuth endpoint is to widen
that case — which is exactly how the forbidden one would get added. So
`TestTheAuthorizationEndpointNeverGetsCORS` asserts it, and the mutation that
adds `oidc.PathAuthorize` to that case fails it.

## Where the allowed origins come from

The origins of the client's own **registered redirect URIs** — nothing else, and
no new setting.


Private-use scheme redirects (`com.example.app:/cb`) are skipped: a native app
has no browser origin and cannot be the source of a cross-origin fetch.

The set is cached for a minute. On a database error the previous answer is served
rather than an empty one — returning nothing would refuse every SPA at once, and
this list only ever widens what a browser may *read*, never what it may *do*.

## Credentials are never allowed

`Access-Control-Allow-Credentials` is absent from every response, and a test
enforces that it stays absent.

OAuth clients authenticate with a secret or an assertion inside the request, not
with ambient cookies. Our session cookie is `__Host-` prefixed and SameSite=Lax
precisely so it does not travel cross-site; setting the credentials flag
alongside a reflected origin would undo that on the endpoints where it matters
most, in exchange for nothing a real client needs.

The test skips comment lines, because `cors.go` names the header in prose to
record why it is absent — and a check that cannot tell an explanation from an
implementation would force the explanation to be deleted.

## Verified against a live server

| Request | Result |
|---|---|
| Preflight `POST /oauth2/token`, `Origin: https://app.example` (registered) | 204 with `Allow-Origin: https://app.example`, `Allow-Methods`, `Allow-Headers`, `Max-Age`, `Vary: Origin` |
| Same, `Origin: https://evil.example` (not registered) | 204 with **no** CORS headers — the browser refuses the real request |
| Preflight `GET /oauth2/authorize` from a registered origin | 204 with **no** CORS headers |
| `GET /.well-known/openid-configuration` from any origin | `Allow-Origin: *` |
