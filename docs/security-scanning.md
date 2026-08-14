# Static analysis

```sh
cd engine
govulncheck ./...
gosec -exclude=G101 ./...
```

## gosec

Previously reported in this project as **"not run"** rather than as passing,
because it exited 0 having analysed nothing when its dependency fetches timed
out. Exit code alone was not evidence. It now runs properly:

```
Files : 76
Lines : 21330
Issues: 33      # at the time of the first real run
```

The baseline is now **23** with `-exclude=G101` (12 open redirects, 4 operator
file paths, 1 path traversal, 1 `template.URL`). It moves only when a new
redirect site or file read is added, and each addition is checked by hand
against the table below before the number is accepted.

The most recent move, 22 -> 23, was **G710 at `samlslo.go`**: the `LogoutResponse`
now leaves on the HTTP-Redirect binding when that is what the provider registered,
which is a new `http.Redirect` site. The destination comes from
`core.saml_slo_urls` for a provider whose signature has already verified against
its registered certificate -- an operator-configured URL, not a request parameter
-- and `SignRedirectQuery` percent-encodes the RelayState it appends. Same class
as the other eleven.

Checking it did surface something real, though: `RelayState` was bounded on the
SSO path and not on the SLO path. That mattered little while every response went
out as a form field, and matters now that it goes in a URL, where an oversized
value is silently truncated by browsers and proxies -- the provider then receives
a RelayState it never sent. Now bounded at the specification's 80 bytes on both.

Two of the first run's findings were **real** and are fixed:

**G124 — CSRF cookie was not `HttpOnly`.** The double-submit pattern is sometimes
written with a readable cookie so a script can copy it into a header. Nothing
here does: the token is rendered into the form server-side. So script access
bought nothing and cost real defence — an XSS that can read the token can forge
requests that pass the comparison. gosec was right.

**G115 — `signCount` truncated on a narrowing cast.** The WebAuthn counter is a
`uint32` on the wire and an `int64` in the database. A plain cast of an
out-of-range value wraps to a small number, and this counter is the *cloning
detector*: a wrapped value reads as "the counter went backwards", or lets a
replayed assertion look like progress. Now clamped. Not reachable through the
normal path — what goes in came from a `uint32` — but reachable through a
corrupted row, which is exactly when a cloning detector should still behave.

## The 33 that remain, and why

Left visible rather than suppressed. A report that converges to zero by
annotation stops being evidence; this list is the baseline, and anything not on
it is signal.

| rule | count | assessment |
|---|---|---|
| G101 hardcoded credentials | 17 | **False.** Substring matches on protocol constants — `TypLogoutToken = "logout+jwt"`, `PathToken = "/oauth2/token"`, SAML status URNs. No secrets. Excluded by flag rather than 17 annotations. |
| G710 open redirect | 11 | **Guarded, in a different function.** Taint analysis cannot follow the validation. Each site checked by hand — see below. |
| G304 file inclusion | 7 | TLS certificate, key, CA-bundle, client-JWKS, policy-file and GeoIP-database paths from operator configuration. Someone who can set them can already read any file the process can. |
| G703 path traversal | 3 | `SIGNARI_CA_BUNDLE`, `SIGNARI_GEOIP_DB` and the policy file path, same reasoning. |
| G203 no auto-escape | 1 | `template.URL` on the `otpauth://` enrolment URI. Deliberate: `html/template`'s URL sanitiser rewrites unknown schemes to `#ZgotmplZ`, producing a dead QR link with no error anywhere. It only bypasses the *URL* sanitiser — contextual attribute escaping still applies — and the scheme is fixed. |

### Each open-redirect site

| site | what validates it |
|---|---|
| `flow.go:916` | `resumeAfterSignIn` → `parkedReturn`, local paths only, tested |
| `flow.go:975` | `oauth.ErrorRedirect`, reached only on `DispositionRedirect`, which is set only for a *registered* `redirect_uri` — asserted by the conformance preflight |
| `flow.go:1120,1123,1129` | post-logout URI checked against `client_post_logout_redirect_uris` **for that client**; chain URLs come from registered SLO endpoints |
| `forwardauth.go:240` | `validateProxyRedirect` — `core.proxy_hosts` allow-list |
| `federation.go:125` | the provider's own authorize endpoint, from registration/discovery |
| `federation.go:348` | `validFederationReturn` → `parkedReturn`, stored server-side at flow start |
| `samlchain.go:200` | `core.saml_slo_urls`, https-constrained by a CHECK |
| `samlchain.go:228` | the already-validated post-logout target, stored when the chain began |
| `consent.go:183` | a relative path on this origin |

The pattern is deliberate: validation happens once, in a named function with
tests, and the redirect site receives an already-checked value. That is the
right shape and it is invisible to taint analysis, so the finding is expected
rather than dismissed.

## Annotated in code

Eight `#nosec` annotations, each with the reason at the site:

- **md5 and sha1 in `internal/passwords/foreign.go`** — verifying hashes made by
  *other systems* during a migration. Verifying a legacy hash requires the legacy
  algorithm. Nothing here creates one: every verified credential is immediately
  re-hashed with Argon2id, which is the point.
- **sha1 in `internal/mfa/totp.go`** — RFC 6238 specifies HMAC-SHA1 and every
  authenticator app implements it. HMAC-SHA1 is unaffected by the collision
  attacks that retired SHA-1 for signatures, and choosing SHA-256 would produce
  codes Google Authenticator cannot generate.
- **`InsecureSkipVerify` in `internal/proxycheck`** — operator-selected via
  `-insecure`, and the report prints a line saying so whenever it is on.
- **md5 and HMAC-MD5 in `internal/radius`** — RFC 2865 specifies MD5 for the
  Response Authenticator and RFC 3579 specifies HMAC-MD5 for
  Message-Authenticator. There is no version of RADIUS that uses anything else,
  and the HMAC is precisely what defends against the MD5 collision attack
  (CVE-2024-3596) that the bare construction is vulnerable to.
- **Three integer conversions** bounded by their inputs.

## govulncheck

**It was not clean, and I had said it was.** Running it properly found **seven
standard-library advisories** reachable from this code on Go 1.26.5:

| advisory | package | why it mattered here |
|---|---|---|
| GO-2026-6088 | `encoding/xml` | every SAML document is parsed with it |
| GO-2026-6218 | `net/url` | every redirect and DN validation parses URLs |
| GO-2026-6091 | `html/template` | every page we render |
| GO-2026-6090 | `crypto/tls` | every connection |
| GO-2026-6089, GO-2026-5026 | `net/http` | reachable from the federation client |
| GO-2026-5972 | `encoding/asn1` | reachable via certificate parsing |

All seven are fixed in **go1.26.6**. The toolchain was upgraded and `go.mod` now
requires it, with the reason recorded there — building with an older toolchain
reintroduces all seven and nothing else in the repository would say so.

```
Your code is affected by 0 vulnerabilities.
```

The lesson is the same one this project keeps relearning: a tool reporting
success is not the same as a tool having run. I had carried "govulncheck is
clean" forward from an earlier run rather than re-running it after adding SAML,
federation, SCIM and LDAP.
