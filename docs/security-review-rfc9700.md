# Security review: RFC 9700, requirement by requirement

RFC 9700 — *OAuth 2.0 Security Best Current Practice*, BCP 240 — is the current
security standard for this stack as of August 2026. It is a BCP, not an
informational note: its §2 carries MUST-level requirements on authorization
servers.


## §2.1 Protecting redirect-based flows

| Requirement | Level | Signari |
|---|---|---|
| Exact string matching of redirect URIs | MUST | yes — `HasRedirectURI`, byte equality |
| **Variable port numbers for loopback native apps** | **MUST** | **was missing — now implemented** |
| No open redirectors | MUST NOT | no forwarding of arbitrary query-supplied URIs |
| Avoid forwarding user credentials on redirect (§4.12) | MUST | credentials are never placed in a redirect |

### The defect: native apps could not use Signari at all

RFC 9700 §4.1.3, immediately after mandating exact matching:

> The only exception is native apps using a localhost URI: In this case, the
> authorization server **MUST allow variable port numbers** as described in
> Section 7.3 of [RFC8252].

RFC 8252 §7.3 gives the reason:

> The authorization server **MUST allow any port** to be specified at the time of
> the request for loopback IP redirect URIs, to accommodate clients that obtain
> an available ephemeral port from the operating system at the time of the
> request.

`HasRedirectURI` was pure string equality, with a test asserting that even
`https://app.example:443/cb` must not match `https://app.example/cb`. That
strictness is right for public hosts and wrong for the one case both RFCs carve
out. A desktop app cannot know its port before asking the operating system for
one: it registers `http://127.0.0.1:1234/cb`, listens on 51004, and was refused.

This is the failure mode where "our implementation is simpler, therefore
better" turns out to be wrong. Simpler was not stricter here — it made a whole
client class impossible.

`loopbackPortMatch` now allows the port, and only the port, to differ. Both sides
must be `http`, the host must be the *same* loopback host (`127.0.0.1` and `::1`
are different addresses), and path, query and fragment must match exactly.


## §2.1.1 Authorization code grant

| Requirement | Level | Signari |
|---|---|---|
| Support PKCE | MUST | yes |
| Enforce `code_verifier` when a challenge was sent | MUST | yes |
| Mitigate PKCE downgrade: verifier accepted only if a challenge was present | MUST | **fixed this session** — see `protocol-review-oauth.md` |
| Provide a way to detect PKCE support | MUST | `code_challenge_methods_supported` in metadata |
| Prefer challenge methods that do not expose the verifier | SHOULD | S256 only; `plain` refused outright |
| Detect constant PKCE challenge / nonce values | encouraged | **not implemented** — see below |

The one §2.1.1 item not covered is the encouragement to detect constant
challenge values. It is not a MUST and it is genuinely awkward — distinguishing
a client that reuses a challenge from one that legitimately retries needs state
per client over time. Recorded as a gap rather than quietly omitted.

## §2.2 Token replay prevention

| Requirement | Level | Signari |
|---|---|---|
| Sender-constrain access tokens (mTLS or DPoP) | SHOULD | both: RFC 8705 `x5t#S256` and RFC 9449 `jkt` |
| Public-client refresh tokens sender-constrained **or** rotated | MUST | rotation with reuse detection (`store/refresh.go`) |

## §2.3 Access token privilege restriction

| Requirement | Level | Signari |
|---|---|---|
| Audience-restrict access tokens | SHOULD | yes — `aud` is the client, or the RFC 8707 `resource` values |
| **Resource server MUST refuse a token not meant for it** | **MUST** | **was missing — now enforced** |

### The second defect: we did not enforce audience against ourselves

`VerifyAccessTokenAny` checked signature, `typ`, `iss`, `sub`, `exp`, `iat` and
`jti` — and never looked at `aud`. Meanwhile the mint path sets the audience to
the RFC 8707 `resource` values whenever a client sends them.

So a client could request a token for `https://api.example`, receive one whose
audience says exactly that, and then spend it at our own `/userinfo` to read the
subject's profile. §2.3 is explicit about whose job that is:

> every resource server is obliged to verify, for every request, whether the
> access token sent with that request was meant to be used for that particular
> resource server. If it was not, the resource server **MUST refuse** to serve
> the respective request.

We are a resource server for our own endpoints. This is the "Compromised
Resource Server" case of §4.9.2: whoever holds a token meant for one API —
including that API, if it is compromised — should not be able to turn it on a
different one. An audience restriction the issuer declines to enforce against
itself is decoration.

`tokens.AudienceAccepted` now gates `/userinfo`. It accepts the client the token
was issued to (so ordinary OIDC is unaffected) or this issuer named explicitly as
a resource. A client wanting one token for both asks for both, which is what RFC
8707 §2's multiple `resource` parameters are for — rather than getting the second
for free because nobody checked. An absent `aud` is refused rather than treated
as a wildcard: RFC 9068 §4 requires the claim.

## §2.4 – §2.6

| Requirement | Level | Signari |
|---|---|---|
| Resource owner password credentials grant | MUST NOT | refused in `ValidateGrantType` |
| Enforce client authentication where feasible | SHOULD | yes, and shared across every direct-request endpoint |
| Asymmetric client authentication available | RECOMMENDED | `private_key_jwt` and mutual TLS |
| Publish authorization server metadata | RECOMMENDED | RFC 8414 discovery |
| Clients must not influence `client_id` | SHOULD NOT | dynamic registration assigns it; the request cannot choose it |
| Authorization responses never over unencrypted connections | MUST | `ValidateRedirectURI` refuses non-loopback `http` |
| **CORS MUST NOT be supported at the authorization endpoint** | **MUST NOT** | satisfied — no CORS anywhere |


## §4 attack-specific countermeasures

| Attack | Countermeasure | Signari |
|---|---|---|
| §4.1 Insufficient redirect URI validation | exact matching + loopback exception | yes |
| §4.2 Leakage via `Referer` | no credentials in URLs beyond the response itself | yes |
| §4.3.1 Code in browser history | code is single-use and short-lived | yes |
| §4.3.2 Token in browser history | never accepted from a query string | yes |
| §4.4 Mix-up | RFC 9207 `iss` in the authorization response | yes, on by default |
| §4.5 Code injection | PKCE required by default | yes |
| §4.6 Access token injection | no implicit grant; code flow only | yes |
| §4.7 CSRF | double-submit `__Host-` cookie, constant-time compare | yes |
| §4.8 PKCE downgrade | verifier refused without a challenge | fixed this session |
| §4.10.1 Stolen token misuse | DPoP and mTLS sender-constraining | yes |
| §4.10.2 Audience restriction | enforced at our own resource | fixed above |
| §4.11.2 AS as open redirector | redirect targets are registered, never request-supplied | yes |
| §4.13 TLS-terminating proxies | URLs built from the configured issuer, never `Host` | yes |
| §4.14 Refresh token protection | rotation with reuse detection and family revocation | yes |
| §4.16 Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY` | yes |
| §4.17 In-browser communication | no `postMessage` response mode implemented | not applicable |

## Verdict

Two MUST-level defects found and fixed: the loopback port exception (§2.1 /
§4.1.3), and audience enforcement at our own resource server (§2.3). Both were
invisible to the existing tests because both were *absences* — one check that
was too strict and one that was not there at all.

One MUST NOT is satisfied only because the corresponding feature is unbuilt
(CORS), and that is stated rather than counted as a win. One encouragement
(constant-PKCE-value detection) is not implemented and is recorded as such.

Every fix in this document is mutation-tested: the guard was removed or inverted
and the naming test observed to fail.
