# Static analysis

## Introduction

"Static analysis" means reading a program's source for known kinds of bug,
without running it. Signari runs three tools of this kind. The first, govulncheck,
looks for known vulnerabilities that the code can reach. The second, gosec, looks
for risky patterns in Go, one function at a time. The third, CodeQL, follows a
value across functions and packages.

This page records how each tool is run, every finding that remains and why, and
the real defects the findings led to. It also records the hand-run "sweeps" for
code that is built but unreachable, and which of them became tests.

It is for a security reviewer who wants the evidence behind a clean result, and
for a contributor whose change moves a count. When a run fails on a finding, the
sections below show how earlier findings were traced and decided.

## Run the scanners

These two commands run govulncheck over the engine, and gosec against its
baseline:

```sh
cd engine && govulncheck ./...
scripts/gosec-check.sh        # from the repository root
```

`scripts/gosec-check.sh` runs `gosec -exclude=G101` and compares its findings,
per rule and per file, with [the reviewed baseline](../engine/gosec-baseline.txt).
It fails on any finding the baseline does not already account for. It also reports
any count that has fallen, so that the baseline can be lowered in the same change.

The baseline is the reviewed list, with the reason for each class beside it. A
total on its own let a new finding hide behind one that had gone away.

## gosec

This project used to report gosec as **"not run"**, not as passing. When its
dependency fetches timed out, it exited 0 having analysed nothing, so the exit
code alone was not evidence. It now runs properly:

```
Files : 76
Lines : 21330
Issues: 33      # at the time of the first real run
```

The most recent move, 22 -> 23, was **G710 at `samlslo.go`**. The
`LogoutResponse` now leaves on the HTTP-Redirect binding when that is what the
provider registered, which is a new `http.Redirect` site.

The destination comes from `core.saml_slo_urls`, for a provider whose signature
has already verified against its registered certificate. It is a URL an
administrator configured, not a request parameter. `SignRedirectQuery`
percent-encodes the RelayState it appends. It is the same class as the other
eleven.

Checking it did surface something real, though: `RelayState` was bounded on the
single sign-on (SSO) path, and not on the Single Logout (SLO) path. That mattered
little while every response went out as a form field. It matters now that it goes
in a URL. Browsers and proxies silently truncate an oversized value there, and the
provider then receives a RelayState it never sent. It is now bounded at the
specification's 80 bytes on both.

Two of the first run's findings were **real** and are fixed:

**G124 — cross-site request forgery (CSRF) cookie was not `HttpOnly`**. A CSRF
token is sometimes kept in a readable cookie, so that a script can copy it into a
header. Nothing here does: the token is rendered into the form server-side. So
script access bought nothing and cost real defence. A cross-site scripting (XSS)
flaw that can read the token can forge requests that pass the comparison. gosec
was right.

**G115 — `signCount` truncated on a narrowing cast.** The WebAuthn counter is a
`uint32` on the wire and an `int64` in the database. A plain cast of an
out-of-range value wraps to a small number, and this counter is the *cloning
detector*. A wrapped value reads as "the counter went backwards", or lets a
replayed assertion look like progress. It is now clamped.

The cast is not reachable through the normal path, because what goes in came from
a `uint32`. It is reachable through a corrupted row, which is exactly when a
cloning detector should still behave.

## The 33 that remain, and why

They are left visible, not suppressed. A report that converges to zero by
annotation stops being evidence. This list is the baseline, and anything not on
it is signal.

| rule | count | assessment |
|---|---|---|
| G101 hardcoded credentials | 17 | **False.** Substring matches on protocol constants — `TypLogoutToken = "logout+jwt"`, `PathToken = "/oauth2/token"`, Security Assertion Markup Language (SAML) status URNs. No secrets. Excluded by flag rather than 17 annotations. |
| G710 open redirect | 11 | **Guarded, in a different function.** Taint analysis cannot follow the validation. Each site checked by hand — see below. |
| G304 file inclusion | 7 | Transport Layer Security (TLS) certificate, key, CA-bundle, client-JWKS, policy-file and GeoIP-database paths from the administrator's configuration. Someone who can set them can already read any file the process can. |
| G703 path traversal | 4 | `SIGNARI_CA_BUNDLE`, `SIGNARI_GEOIP_DB`, `SIGNARI_GEOIP_ASN_DB` and the policy file path, same reasoning. |
| G203 no auto-escape | 1 | `template.URL` on the `otpauth://` enrolment URI. Deliberate: `html/template`'s URL sanitiser rewrites unknown schemes to `#ZgotmplZ`, producing a dead QR link with no error anywhere. It only bypasses the *URL* sanitiser — contextual attribute escaping still applies — and the scheme is fixed. |

### Each open-redirect site

| site | what validates it |
|---|---|
| `flow.go:916` | `resumeAfterSignIn` → `parkedReturn`, local paths only, tested |
| `flow.go:975` | `oauth.ErrorRedirect`, reached only on `DispositionRedirect`, which is set only for a *registered* `redirect_uri` — asserted by the conformance preflight |
| `flow.go:1120,1123,1129` | `post_logout_redirect_uri` checked against `client_post_logout_redirect_uris` **for that client**; chain URLs come from registered SLO endpoints |
| `forwardauth.go:240` | `validateProxyRedirect` — `core.proxy_hosts` allow-list |
| `federation.go:125` | the provider's own authorize endpoint, from registration/discovery |
| `federation.go:348` | `validFederationReturn` → `parkedReturn`, stored server-side at flow start |
| `samlchain.go:200` | `core.saml_slo_urls`, https-constrained by a CHECK |
| `samlchain.go:228` | the already-validated sign-out target, stored when the chain began |
| `consent.go:183` | a relative path on this origin |

The pattern is deliberate. Validation happens once, in a named function with
tests, and the redirect site receives a value already checked. That is the right
shape, and it is invisible to taint analysis, so the finding is expected rather
than dismissed.

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
- **`InsecureSkipVerify` in `internal/proxycheck`** — administrator-selected via
  `-insecure`, and the report prints a line saying so whenever it is on.
- **md5 and HMAC-MD5 in `internal/radius`** — RFC 2865 specifies MD5 for the
  Response Authenticator and RFC 3579 specifies HMAC-MD5 for
  Message-Authenticator. There is no version of Remote Authentication Dial-In User Service
  (RADIUS) that uses anything else,
  and the HMAC is precisely what defends against the MD5 collision attack
  (CVE-2024-3596) that the bare construction is vulnerable to.
- **Three integer conversions** bounded by their inputs.

## govulncheck

**It was not clean, and this page had said it was.** Running it properly found
**seven standard-library advisories** reachable from this code on Go 1.26.5:

| advisory | package | why it mattered here |
|---|---|---|
| GO-2026-6088 | `encoding/xml` | every SAML document is parsed with it |
| GO-2026-6218 | `net/url` | every redirect and DN validation parses URLs |
| GO-2026-6091 | `html/template` | every page we render |
| GO-2026-6090 | `crypto/tls` | every connection |
| GO-2026-6089, GO-2026-5026 | `net/http` | reachable from the federation client |
| GO-2026-5972 | `encoding/asn1` | reachable via certificate parsing |

All seven are fixed in **go1.26.6**. The toolchain was upgraded, and `go.mod` now
requires it, with the reason recorded there. Building with an older toolchain
reintroduces all seven, and nothing else in the repository would say so. After
the upgrade, govulncheck reported:

```
Your code is affected by 0 vulnerabilities.
```

The lesson is the same one this project keeps relearning: a tool reporting
success is not the same as a tool having run. "govulncheck is clean" had been
carried forward from an earlier run. It had not been run again after support for
federation and Security Assertion Markup Language (SAML) was added. Nor had it run
after System for Cross-domain Identity Management (SCIM) and Lightweight Directory
Access Protocol (LDAP) arrived.

### Seven weeks later: twelve more, and a module

Nothing had changed in this code; the world had. The next run on go1.26.6 found
twelve standard-library advisories reachable from the engine, and one in a
module:

| advisory | package | why it mattered here |
|---|---|---|
| GO-2026-6599, GO-2026-6600 | `html/template` | every page we render |
| GO-2026-6603, GO-2026-6610, GO-2026-6611, GO-2026-6612, GO-2026-6617 | `net/http` (HTTP/2) | memory, CPU and crash in an HTTP/2 server; malformed framing accepted by the transport |
| GO-2026-6605, GO-2026-6613 | `net/http` (HTTP/1) | connection desynchronisation around CONNECT |
| GO-2026-6608 | `net/textproto`, `mime/multipart` | header-size limit bypass on every request |
| GO-2026-6609 | `net/http` | unbounded Range header parsing |
| GO-2026-6607 | `crypto/tls` | malformed Encrypted Client Hello (ECH) extension references |
| GO-2026-6629 | `golang.org/x/text` | panic in PRECIS, which normalises usernames |

All are fixed in **go1.26.9** and `golang.org/x/text` v0.41.0.

A later scan on go1.26.9 found **GO-2026-6809**. `crypto/x509` kept trusting
intermediate certificates that have since been distrusted. It was reachable from
the FIDO metadata check, which decides whether a security key's attestation is
anchored. It is fixed in **go1.26.10**.

The release script refused to build until the toolchain moved, which is what it is
for. In November 2026 it refused again. On go1.26.10 it found **GO-2026-6859**, an
HTTP/1 server crash through a header race in `http.MaxBytesReader`. That function
bounds request bodies on two dozen paths here. It is fixed in **go1.26.11**, now
the floor in each module's `go.mod` and in every build image.

The Terraform provider had fifteen of its own, gRPC authorization bypass and
memory exhaustion among them. They were fixed by the same toolchain and newer
`grpc`, `x/net` and `x/text`.

A clean result is only true on the day it was produced. So continuous integration
(CI) runs govulncheck on every change, instead of this page recording a verdict.

## CodeQL

[The CodeQL workflow](../.github/workflows/codeql.yml), in
`.github/workflows/codeql.yml`, runs CodeQL over every Go module, the TypeScript
and JavaScript, and the workflows. CodeQL follows a value from a request across
functions and packages to a "sink", the place where the value is used. By
contrast, gosec reads one function at a time, so it does not.

CodeQL's findings go to the repository's code scanning alerts, and do not fail the
job. So, like gosec's baseline, they are read rather than trusted.

Its first run, 21 November 2026, opened 101: 5 critical, 84 high, 12 medium. Each
was traced to its source by hand. None is a defect in shipped code. By rule:

| Rule | Count | Why it is not a defect |
|---|---|---|
| `go/request-forgery` | 4 (critical) | The URL is a stranger's by design: a federation entity's statement, a `sector_identifier_uri`, a client ID metadata document, Duo's configured API host. Every one is fetched through `safedial`, which refuses private, loopback and link-local addresses at the moment of connection, after DNS, where taint analysis cannot see it. `Server.outboundHTTP`, the one way to swap the client, is set only by tests. |
| `go/email-injection` | 1 (critical) | Headers are built, not interpolated: CR and LF are stripped from every header value, the subject is RFC 2047 encoded, the recipient must parse as an address, and `net/smtp` refuses a line break in `MAIL` and `RCPT` itself. The HTML part is `html/template`. |
| `go/clear-text-logging` | 43 | Each logs a client id, a grant type, a scope name or an error. A client id is not a secret. CodeQL taints the whole `Authorization` header the id was parsed from, secret included, and none of the errors carries the presented secret: client authentication's are fixed strings ("the client secret did not match"). `SecretRef.String` prints the reference (`$NAME` or a path), never the value, and a password-hash cost refusal names only the costs. |
| `go/weak-sensitive-data-hashing` | 17 | MD5 and SHA-1 to verify the hashes of a directory being migrated off, never to make one, and a password that verifies is rehashed with Argon2id at once; and the MD5 constructions RFC 2865 §5.2 and RFC 2548 specify for RADIUS. |
| `go/unvalidated-url-redirection` | 11 | Every destination is registered or checked: a client's registered `redirect_uri`, sign-in page or `post_logout_redirect_uri`; a configured SAML sign-out endpoint; `validateProxyRedirect` against `core.proxy_hosts`; `parkedReturn`, which takes only a single-slash path on this origin; a return target sealed server-side. The eleventh is the benchmark's own test upstream. The section above has the same sites as gosec saw them. |
| `go/reflected-xss` | 6 | Each is the `Write` of a response-writer wrapper passing bytes through (tracing, metrics, recovery, the access log, the token endpoint's status recorder, the form-redirect writer). The page the form-redirect writer composes escapes every value with `html.EscapeString`, under `default-src 'none'`. |
| `go/uncontrolled-allocation-size` | 6 | A list sized by `limit`, which `pageParams` caps at 200. |
| `go/allocation-size-overflow` | 3 | Sums of the lengths of things already in memory: a rendered page, an audit record's detail map. |
| `go/incorrect-integer-conversion` | 2 | Argon2 iterations and parallelism from the environment, refused below the defaults (2 and 1) and above 16 before the conversion; CodeQL does not see a bound checked inside a closure. |
| `js/polynomial-redos` | 1 | The TypeScript SDK trims trailing slashes from the endpoint its own caller passes to the constructor. That is the developer's configuration, not an attacker's input. |
| `js/*` in `interop/`, `tools/`, `examples/` | 6 | Test pages and tools run by whoever runs the tests, and a quickstart with no rate limiting, which an example of how to sign in does not need. The preflight's "incomplete URL sanitization" is an assertion that the engine refused an attacker's address. |

A new alert is read the same way. One this table does not explain is either a
defect or a new row here.

## SHA-1 in `internal/saml/encrypt.go`

G505 and G401 fire on `crypto/sha1` there. Both are annotated `#nosec`, with the
reason at the line, instead of being excluded globally.

The SHA-1 is inside RSA-OAEP's mask generation function, in the key transport
algorithm `rsa-oaep-mgf1p`. That is the one every SAML application implements.
MGF1 needs a pseudorandom function (PRF), not collision resistance, and SHA-1 is
still a fine PRF.

That is a different question from SHA-1 in a *signature*. There, chosen-prefix
collisions are practical, and this package refuses SHA-1 outright, on both SAML
bindings.

Excluding G505 across the repository would have hidden any future SHA-1 that *is*
in a signature, which is the finding that would matter.

The 23 -> 24 move was a new `G304` in `saml add-sp`. It reads the
`-sp-encryption-cert` file an administrator names on the command line, the same
class as the other file paths an administrator sets.

## G203 on the TOTP enrolment page

The time-based one-time password (TOTP) enrolment page has two now: `template.URL`
for the `otpauth://` link, and `template.HTML` for the inline QR code SVG. Both
turn off escaping, and both are annotated at the line.

The SVG is generated entirely from integers and literals. The QR payload becomes a
matrix of booleans, and is emitted as `%d` path coordinates, so no text a person
supplies reaches the markup.

That is asserted rather than argued.
`TestSVGContainsNothingButGeneratedMarkup` pushes
`</svg><script>alert(1)</script>` through the encoder. It requires exactly four
opening and four closing brackets in the result. See `docs/totp-qr.md`.

## Sweeping for "built but unreachable"

Two real bugs found in one session had the same shape: code that worked, was
tested, and that nothing could actually reach. Both are mechanically detectable,
so the checks are written down instead of left to luck.

**Packages nothing imports.** This is how the RADIUS listener was missing:
`internal/radius` was complete, and imported by no file outside itself. To list
such packages, from `engine/`:

```sh
for d in internal/*/; do
  pkg=$(basename "$d")
  n=$(grep -rl "signari.dev/engine/internal/$pkg\"" --include="*.go" . |
       grep -v "^./internal/$pkg/" | wc -l)
  [ "$n" = "0" ] && echo "UNIMPORTED: internal/$pkg"
done
```

**Documented configuration that does not exist.** `SIGNARI_RADIUS_CLIENTS` was
documented as the way to configure devices, and was never read by any code. To
list settings the docs name and the code never reads:

```sh
grep -rhoE "SIGNARI_[A-Z0-9_]+" docs/ *.md | sort -u > /tmp/doc_envs
grep -rhoE "SIGNARI_[A-Z0-9_]+" engine/ --include="*.go" | sort -u > /tmp/code_envs
comm -23 /tmp/doc_envs /tmp/code_envs
```

**Columns nothing reads.** This is how `want_authn_requests_signed` sat
unenforced, and how `ssf_streams.auth_token` was never sent. To list columns no Go
file names:

```sh
psql -tAc "SELECT table_name||'.'||column_name FROM information_schema.columns
           WHERE table_schema='core'" |
while read -r c; do
  grep -rqw "${c#*.}" --include="*.go" . || echo "UNREAD: core.$c"
done
```

All three are clean as of this writing, except for benign timestamps written by
`DEFAULT now()` and read only by cleanup SQL. The last check is the noisiest, and
still the most valuable: a stored setting nothing reads is a promise the system
does not keep.

## The unread-column sweep earning its keep

The sweep was run against the tables added for the device flow, email codes and
dynamic registration. It found one: `email_otp_credentials.enrolled_at`, sitting
beside `created_at`, both with `DEFAULT now()`, and neither ever read.

Two columns holding the same fact raise a question about which is authoritative.
Everybody who reads the schema afterwards has to ask it. The column was dropped in
migration 0042, the same day it was written.

## When the baseline moves because the tool did

The gosec count went from 33 to 53 in one run, with no relevant code change. The
whole jump was two new taint-analysis rules in a newer gosec: **G703** (path
traversal, 5) and **G710** (open redirect, 12). Three `G304` file reads in new
code made up the rest.

A tool upgrade that raises the number is the moment to check the findings, not to
update the baseline. An open redirect in an authorization endpoint is precisely
the bug worth being wrong about. So all twelve were verified against a running
engine, not by reading:

```
unregistered redirect_uri + an invalid request   400, rendered here, no redirect
registered redirect_uri + an invalid request     303 to the registered URI, with iss
unregistered post_logout_redirect_uri            400, no redirect
return=//evil.test  through a full sign-in       resumed on the engine's own origin
```

Every flagged redirect resolves its destination through a database allow-list,
or through a same-origin path check. The allow-lists are
`core.client_redirect_uris`, `core.proxy_hosts` and the configured SAML SLO
endpoint.

gosec's taint analysis cannot see through a database round trip, so it flags the
query result as attacker-controlled. It is right that the value came from the
request, and wrong that nothing checked it in between.

The rules stay on. A false positive costs an hour of live verification, once.
That is a better trade than switching off the rule that would have caught the real
one.

**Baseline: 53, all reviewed.** Verified against `signari serve`, not by reading.

### 53 to 71, and the two that were real

The next run found 73. Twenty findings had arrived with new code and newer rules,
and each was traced to its source instead of being added to the total:

- **G116, Trojan Source — real.** `internal/i18n/printer.go` held its two isolate
  characters as raw bytes, and two test files held fifteen more invisible
  characters the same way. Now written as escapes, and
  `TestNoInvisibleFormattingCharacterIsWrittenRaw` fails the build on any raw
  bidirectional, zero-width or separator character in a tracked file.
- **G114 — real, if minor.** The remote-access test harness served with no header
  deadline; it now has one.
- **G115 ×3** in `internal/radius/authorization.go` — `taggedInteger` splits a
  three-octet RFC 2868 value into bytes on purpose, and is called with constants.
- **G705** — the trust-mark endpoint writes a JSON Web Token (JWT) under its own media type with
  `nosniff`; no browser renders it as HTML.
- **G117, G203, G204, G301, G306** — a protocol field named `access_token`;
  catalogue text marked safe only after every value is escaped; `kadmin` argv
  with no shell; ejected theme templates and a QR image written world-readable,
  none of them secrets.
- **G710 rose to 14** with the sign-out chain, federation return and Duo: every
  destination again resolves through a registered value, configuration, or the
  same-origin check in `parkedReturn`.

**Baseline: 71**, listed by rule and file in `engine/gosec-baseline.txt` and
enforced by `scripts/gosec-check.sh`.

**70** after the Duo hand-off was split, so that the health probe reads inside the
sign-in's transaction and the redirect happens after it is released. The redirect
target is still `AuthorizeURL` on the configured API host. gosec no longer follows
it across the two functions.

**71** when `SIGNARI_CA_BUNDLE` moved into `safedial`, which reads it once at
startup so that every outbound client trusts it, not only delivery. It is a new
`G304` of the administrator-path class above. The delivery path keeps its own
`G304`, because it still reads the older `SIGNARI_SCIM_CA_BUNDLE` when the general
setting is unset.

**78** with the OpenTelemetry Protocol (OTLP) exporter (3.09): seven `G115` in
`internal/tracing/otlp.go`, all of them protobuf encoding. Two shift a field
number and a wire type, both constants, into a key. Four write a length or a
dropped count, none of which can be negative.

The seventh writes an `int64` attribute as `uint64(v)`, its two's complement. That
is how protobuf-go's own encoder writes an `int64`
(`google.golang.org/protobuf` v1.36.12, `internal/impl/codec_gen.go:1851`). The
bytes were decoded with the generated OTLP types, and Jaeger assembled them into
traces.

That count is measured against this change alone. The tree it was made on already
gave 164 against the 71 here. The difference is findings that arrived after the
baseline was last set, and were never reviewed. They are still to be.

### 78 to 177, every one traced

The release build stopped at the gate with 186 findings. Each was traced to where
its value comes from, and nine went away:

- **One was real.** The passkey importer narrowed an export's signature counter
  with `uint32(max(n, 0))`. The counter is a "32-bit unsigned big-endian
  integer" (`specs/webauthn.txt:4873`), so a larger one is not a count any
  authenticator sent, and the cast wrapped it to a small number, a floor a cloned
  authenticator's next assertion clears. Such a passkey is now refused and named in
  the report, and the person enrols it again.
- **Three annotations gosec could not read.** `//nolint:gosec` is another linter's
  syntax; gosec reads `#nosec`. That covered the `x5t` SHA-1 thumbprint in
  federation token authentication. MPPE's `#nosec` on the md5 import sat above
  `"context"` once the imports were sorted, so it annotated the wrong line.
  md5-crypt (4.09) now carries the same annotation as the other foreign-hash
  verifiers in `foreign.go`.
- **The command line, 74 new and 111 in all.** Every `G304` and `G703` in `cmd/signari` is a
  path the administrator names with a flag, or a secret file the administrator's
  configuration names. The Admin API refuses such a file outright, and the command
  line refuses one that an engine setting names. Most of the jump is gosec's
  `G703` ignoring the `#nosec G304` already on eighteen of these lines. The two
  `G704` are the command line's Admin API client calling the address the administrator
  gave.
- **Nine new open-redirect sites**, of four kinds:
  - The request's own routed path, sent back as a GET so the session cookie comes
    with it: `saml.go`, `samlartifactrequest.go` and `wsfed.go`.
  - A configured address: an external factor's URL, or an upstream's SLO endpoint.
  - The sign-out target, checked against the client's registered URIs. It is
    then either carried through the upstream under the root key's MAC
    (`upstreamlogout.go`) or stored server-side when the sign-out began
    (`samlsourcelogout.go`).
  - A fixed path: `/authorize` on this origin. The forward-auth callback is built
    from the host `validateProxyRedirect` accepted.

The two kinds that act on what the request carries, its path and a returned
state, are the class the rule exists for. They were checked against
`signari serve`, not by reading:

```
/logout/complete, a target with a forged mark, no mark, or an empty one   200, no redirect
POST //wsfed and POST ///evil.test/../saml/sso, cross-site                 307 to this origin's /wsfed, /saml/sso
POST /wsfed cross-site                                                     303 to /wsfed?wa=... on this origin
POST /wsfed/org/x/..%2f..%2f..%2fevil.test                                 404
```

`ServeMux` cleans a doubled slash or a dot segment before any handler sees the
path, so `r.URL.Path` there cannot begin `//`.

The rest are false positives:

- `G407`: `cipher.NewGCMWithRandomNonce` makes its own nonce, and `nil` is how it
  is asked to.
- `G124`: a cookie set on the in-process sub-request a headless step replays.
  Nothing here is a `Set-Cookie`.
- `G117`: a provider's tokens marshalled only to be sealed under the root key.
- `G402`: TLS 1.2 is the tunnel's ceiling because RFC 5281's and MS-PEAP's keys
  are defined over its PRF.
- `G705`: a signed request object, with `nosniff`.
- `G203`: the enrolment QR and URI, the same as `enrol.go`'s.
- `G115` ×5: each value is bounded before the conversion.

**177 to 179:** one `G304` and its `G703` twin in `cmd/signari/oid4vp.go`. They
are the `-root-cert` file `idp vp-issuer` reads, to believe an issuer by its
certificate chain. It is a path the administrator names on their own command line,
the class above. What is read has to be whole PEM CA certificates or it is
refused. Nothing in it leaves the process but the certificates themselves.

**179 to 181:** two in `internal/httpapi/oid4vp.go`, from the wallet on another
device. A `G203` for the QR code's SVG, which the encoder writes from a matrix of
booleans, as the enrolment page's is. A `G710` on the redirect to the wallet,
which was there before.

What the request now picks is a boolean, this device or the page, and gosec's
taint follows it into the address. The address is the configured wallet URL with
Signari's own `client_id` and `request_uri`. It was checked against
`signari serve` with `device` and `return` set to other origins. Every answer sent
the browser to the wallet URL. `return` reached only the pending sign-in, through
the same validation as every provider's.

**181 to 180:** that `G710` went when the start handler was rebuilt for the
browser's Digital Credentials API. The way to this device now begins its request
in a helper, and redirects to what that returns. So gosec no longer follows the
request's choice into the address. The redirect is the same one, to the same
configured wallet URL.

**180 to 184:** `G304` and `G703`, two each, in `cmd/signari/oid4vp.go`. There,
`idp add` and the new `idp vp-iaca` read, from the file `-root-cert` names, the
IACA certificates an mdoc wallet sign-in believes. It is the administrator's own
flag, on the administrator's own machine, read as the request key and its chain
beside them already are.

**184 to 185:** a `G703` in `internal/risk/asn.go`, the `os.Stat` on the file
`SIGNARI_GEOIP_ASN_DB` names, the twin of `geoip.go`'s. The path is the
administrator's setting, read once at startup; nothing a request carries reaches
it. What is opened has to be a MaxMind-format database describing itself as an
autonomous system number (ASN) or ISP one, or it is refused and logged. One number per address is all that is
read from it.

**Baseline: 185**, every line with its reason in `engine/gosec-baseline.txt`.

## A fourth sweep: exported functions nothing calls

The three sweeps above catch unimported *packages*, documented-but-absent
configuration, and unread *columns*. None of them catches a function. This one
does, and it strips comments first, for the reason given below:

```sh
# Strip comments FIRST -- see below.
python3 - <<'PY'
import os, re
strip = lambda s: re.sub(r'^\s*//.*$', '', re.sub(r'/\*.*?\*/', '', s, flags=re.S), flags=re.M)
defs, body = {}, []
for root, _, files in os.walk('.'):
    if 'testdata' in root: continue
    for f in (f for f in files if f.endswith('.go')):
        p = os.path.join(root, f)
        code = strip(open(p, errors='ignore').read())
        body.append((p, code))
        if not f.endswith('_test.go'):
            for m in re.finditer(r'^func (?:\([^)]*\) )?([A-Z]\w+)\(', code, re.M):
                defs[m.group(1)] = p
for name, deffile in sorted(defs.items()):
    hits = sum(len(re.findall(r'\b'+name+r'\b', s)) - (p == deffile) for p, s in body)
    if hits == 0: print(f'UNCALLED: {deffile}: {name}')
PY
```

### The sweep's own bug

The first version did not strip comments, so a function's **doc comment counted
as a call**. This codebase's style is a name, then a paragraph explaining it.
Anything written that way was invisible to the sweep by construction. It reported
four findings. With comments stripped, the same code reported twelve.

A tool that cannot fail is not evidence.

### What the eight new findings were

Four were `go-webauthn` interface methods, called through the interface. The
rest were real:

| | |
|---|---|
| `PurgeSAMLSourceState` | written the same day and never wired into the janitor |
| `GrantedScopes`, `WithdrawConsent` | **a missing feature** — nothing let a person see or revoke an application's access |
| `Why` (geoip) | `SIGNARI_GEOIP_DB` could be set to an unusable path, every impossible-travel check would report "not checked", and nothing said so |
| `ConstantTimeCodeEqual`, `FamilySize`, `HasEmailOTP`, `LoadEmailOTP` | speculative helpers, deleted |

The consent one is the sharpest. Its doc comment reads: *"Without this a user
can grant access and never see it again, which is consent as a formality rather
than a control."* It was written above a function nothing called. The comment
described the bug, and was filed as a justification.

Two further bugs fell out of building the missing page, and no sweep could have
found either:

- **The consent screen showed the client id.** `client create -name` was
  accepted and discarded — the INSERT wrote `$1` (the id) into `display_name`.
  Every client ever created asked for a person's trust under a name like
  `a7f3-crm-prod`.
- **The consent POST read `client_id` from its own form field** while the
  authoritative value sat in the parked authorization query beside it. Two
  fields that must agree eventually do not: consent recorded for one client,
  flow resumed for another. Now read from the query, with a mismatch refused.

## The sweep that could not see Duo

The exported-function sweep above found that `HasSecondFactor` was missing SMS. A
companion test was written to keep it honest. It asks the database which tables
hold credentials, and fails when the gate does not consult one.

It passed while Duo was a multi-factor authentication (MFA) bypass.

The discovery query matched `%otp_credentials` and `totp_credentials`. Duo's
table is `duo_enrollments`. The enrolment table was written and the challenge was
wired up, but `HasSecondFactor` was not updated. The test that existed precisely
to catch that reported success, because it never looked.

A test that fails to look is not a weak test. It is a no-test that reports
success, which is worse than no test at all: the absence of a test is visible.

The rewrite classifies every credential table **explicitly**, and checks the list
against the live schema in both directions. Its failures read like this:

```
core.duo_enrollments holds second-factor credentials and HasSecondFactor does
not consult it. A user whose only factor is in that table signs in with a
password alone, while their account settings say MFA is on.

core.webauthn_credentials is classified as NOT a second factor, but
HasSecondFactor consults it. One of the two is wrong.
```

Broadening the discovery query immediately turned up two more tables nobody had
decided about, `password_credentials` and `recovery_requests`. Each now carries a
recorded reason for being excluded. A false positive costs one line; a false
negative is an authentication bypass.

**Verified both ways**: with the fix in place the test passes, and with Duo
removed from the query it fails, naming the table.

## A fifth sweep: expiry columns nothing compares

An identity provider stores a lot of `expires_at`. A column written and never
compared is a credential that never expires. Unlike a missing feature, it looks
finished from every angle. To list every expiry-shaped column:

```sh
# every expiry-shaped column, then: does anything compare it?
psql -tAc "SELECT table_name||'.'||column_name FROM information_schema.columns
           WHERE table_schema='core'
             AND (column_name LIKE '%expires%' OR column_name LIKE '%not_after%'
                  OR column_name LIKE '%valid_until%' OR column_name LIKE '%_until')"
```

Match each against `<`, `>`, `<=`, `>=` in the Go source. **Do the matching in
Python, not the shell**. The first attempt put a regex containing `|` and `(`
inside a zsh `$(...)`, and every row came back "NO COMPARISON". That read as 22
catastrophic findings, and was a quoting bug.

A sweep that cannot fail is not evidence. A sweep that fails *loudly in one
direction* is worse, because the noise buries the signal.

### The result

18 of 22 compared in SQL. Three more compared in Go after being scanned into a
`*time.Time`. They were false positives from a SQL-only regex, checked one by one
instead of assumed.

One was real: **`core.signing_keys.certificate_not_after`**, stored and never
read by anything.

SAML certificates here are self-signed for ten years and reused forever, and that
is deliberate. Regenerating one changes the fingerprint, and every SAML
application pinning it starts rejecting assertions. That is the failure that looks
like "SAML randomly stopped working for some users".

The consequence is a cliff nobody stands near until they fall off it. SAML
applications that validate expiry begin refusing every assertion on a date chosen
a decade earlier, and nothing had mentioned it. The column existed for exactly
that check.

`signari doctor` now reports it, at three levels:

```
[CRITICAL] the SAML certificate for key fonp6m7E… expired 5 days ago
[warning ] the SAML certificate for key b7B5aS8Y… expires in 29 days
[info    ] the SAML certificate for key fonp6m7E… expires in 199 days
```

It says nothing at all beyond a year. Re-issuing is **not** automated. It has to
be coordinated with every SAML application that pinned the old fingerprint, which
is a conversation rather than a command. What this can usefully do is turn a
morning into a year of notice.

## The sweeps that became tests

Five sweeps, run by hand and remembered, had found real bugs, and being run by
hand is their weakness. Two are now tests, which is the difference between a
discipline and a mechanism:

```
TestEveryEnvVarIsDocumented      a setting read by the engine, described nowhere
TestNoDocumentedSettingIsUnread  prose promising a control nothing reads
```

The first caught four immediately. `SIGNARI_SMTP_USERNAME`,
`SIGNARI_SMTP_PASSWORD`, `SIGNARI_SMTP_PORT` and `SIGNARI_MAIL_FROM_NAME` were
read by the code and documented nowhere. So **an authenticated mail relay could
not be configured from the documentation**, and mail is what account recovery and
email codes run on.

`SIGNARI_DEVICE_COMPLIANT_HEADER` was missing too, while the policy condition it
feeds, `device_compliant`, was documented. A rule could be written that nothing
could ever satisfy.

Both directions were checked by breaking them deliberately: by removing a
documented setting, then adding an invented one. A test that cannot fail proves
nothing.

### Its own first version was wrong

It scanned comments as well as code, so it reported `SIGNARI_RADIUS_CLIENTS`. That
setting never existed. It is discussed at length in two documents *because* it
never existed, including in this test's own comment saying so. A setting named in a
comment is not a setting the engine reads, so the scan strips comments.

That is the fourth sweep here to be wrong on its first run. The pattern is
consistent enough to write down as a rule: **write the sweep, then break the
thing it checks and confirm it notices**. Every one of these that has been trusted
without that step has been wrong.
