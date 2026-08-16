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


## SHA-1 in `internal/saml/encrypt.go`

G505 and G401 fire on `crypto/sha1` there, and both are annotated `#nosec` with
the reason at the line rather than excluded globally.

The SHA-1 is inside RSA-OAEP's mask generation function, which is the key
transport algorithm `rsa-oaep-mgf1p` — the one every SAML service provider
implements. MGF1 needs a pseudorandom function, not collision resistance, and
SHA-1 is still a fine PRF. That is a different question from SHA-1 in a
*signature*, where chosen-prefix collisions are practical and where this package
refuses it outright, on both SAML bindings.

Excluding G505 across the repo would have hidden any future SHA-1 that *is* in a
signature, which is the finding that would matter.

The 23 -> 24 move was a new `G304` in `saml add-sp`: reading the
`-sp-encryption-cert` file an operator names on the command line, the same class
as the other operator file paths.


## G203 on the TOTP enrolment page

Two now: `template.URL` for the `otpauth://` link, and `template.HTML` for the
inline QR code SVG. Both turn off escaping, and both are annotated at the line.

The SVG is generated entirely from integers and literals — the QR payload becomes
a matrix of booleans and is emitted as `%d` path coordinates, so no user-supplied
text reaches the markup. That is asserted rather than argued:
`TestSVGContainsNothingButGeneratedMarkup` pushes `</svg><script>alert(1)</script>`
through the encoder and requires exactly four opening and four closing brackets in
the result. See `docs/totp-qr.md`.

## Sweeping for "built but unreachable"

Two real bugs this session were the same shape: code that worked, was tested, and
that nothing could actually reach. Both are mechanically detectable, so the
checks are written down rather than left to luck.

**Packages nothing imports.** This is how the RADIUS listener was missing —
`internal/radius` was complete and imported by no file outside itself:

```sh
for d in internal/*/; do
  pkg=$(basename "$d")
  n=$(grep -rl "signari.dev/engine/internal/$pkg\"" --include="*.go" . |
       grep -v "^./internal/$pkg/" | wc -l)
  [ "$n" = "0" ] && echo "UNIMPORTED: internal/$pkg"
done
```

**Documented configuration that does not exist.** `SIGNARI_RADIUS_CLIENTS` was
documented as the way to configure devices and was never read by any code:

```sh
grep -rhoE "SIGNARI_[A-Z0-9_]+" docs/ *.md | sort -u > /tmp/doc_envs
grep -rhoE "SIGNARI_[A-Z0-9_]+" engine/ --include="*.go" | sort -u > /tmp/code_envs
comm -23 /tmp/doc_envs /tmp/code_envs
```

**Columns nothing reads.** How `want_authn_requests_signed` sat unenforced, and
how `ssf_streams.auth_token` was never sent:

```sh
psql -tAc "SELECT table_name||'.'||column_name FROM information_schema.columns
           WHERE table_schema='core'" |
while read -r c; do
  grep -rqw "${c#*.}" --include="*.go" . || echo "UNREAD: core.$c"
done
```

All three are clean as of this writing, except for benign timestamps written by
`DEFAULT now()` and read only by cleanup SQL. The last check is the noisiest and
still the most valuable: a stored setting nothing reads is a promise the system
does not keep.


## The unread-column sweep earning its keep

Run against the tables added for device flow, email codes and dynamic
registration, it found one: `email_otp_credentials.enrolled_at`, sitting beside
`created_at` with both `DEFAULT now()` and neither ever read. Two columns holding
the same fact is a question about which is authoritative, asked of everybody who
reads the schema afterwards. Dropped in migration 0042 the same day it was
written.

## When the baseline moves because the tool did

The gosec count went from 33 to 53 in one run with no relevant code change. The
whole jump was two new taint-analysis rules in a newer gosec: **G703** (path
traversal, 5) and **G710** (open redirect, 12), plus three `G304` file reads in
new code.

A tool upgrade that raises the number is the moment to check the findings, not
to update the baseline. Open redirect in an authorization endpoint is precisely
the bug worth being wrong about, so all twelve were verified against a running
engine rather than by reading:

```
unregistered redirect_uri + an invalid request   400, rendered here, no redirect
registered redirect_uri + an invalid request     302 to the registered URI, with iss
unregistered post_logout_redirect_uri            400, no redirect
return=//evil.test  through a full sign-in       resumed on the engine's own origin
```

Every flagged redirect resolves its destination through a database allow-list
(`core.client_redirect_uris`, `core.proxy_hosts`, the configured SAML SLO
endpoint) or a same-origin path check. gosec's taint analysis cannot see through
a database round trip, so it flags the query result as attacker-controlled — it
is right that the value came from the request, and wrong that nothing checked it
in between.

The rules stay on. A false positive that costs an hour of live verification once
is a better trade than switching off the rule that would have caught the real one.

**Baseline: 53, all reviewed.** Verified against `signari serve`, not by reading.

## A fourth sweep: exported functions nothing calls

The three sweeps above catch unimported *packages*, documented-but-absent
config, and unread *columns*. None of them catches a function.

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
as a call**. Anything written in this codebase's style — a name, then a
paragraph explaining it — was therefore invisible to the sweep by construction.
It reported four findings. Stripping comments, the same code reported twelve.

A tool that cannot fail is not evidence.

### What the eight new findings were

Four were `go-webauthn` interface methods, called through the interface. The
rest were real:

| | |
|---|---|
| `PurgeSAMLSourceState` | written the same day and never wired into the janitor |
| `GrantedScopes`, `WithdrawConsent` | **a missing feature** — nothing let a user see or revoke an application's access |
| `Why` (geoip) | `SIGNARI_GEOIP_DB` could be set to an unusable path, every impossible-travel check would report "not checked", and nothing said so |
| `ConstantTimeCodeEqual`, `FamilySize`, `HasEmailOTP`, `LoadEmailOTP` | speculative helpers, deleted |

The consent one is the sharpest. Its doc comment reads: *"Without this a user
can grant access and never see it again, which is consent as a formality rather
than a control."* It was written above a function nothing called. The comment
described the bug and was filed as a justification.

Two further bugs fell out of building the missing page, neither findable by any
sweep:

- **The consent screen showed the client id.** `client create -name` was
  accepted and discarded — the INSERT wrote `$1` (the id) into `display_name`.
  Every client ever created asked for a user's trust under a name like
  `a7f3-crm-prod`.
- **The consent POST read `client_id` from its own form field** while the
  authoritative value sat in the parked authorization query beside it. Two
  fields that must agree eventually do not: consent recorded for one client,
  flow resumed for another. Now read from the query, with a mismatch refused.


## The sweep that could not see Duo

The exported-function sweep above found `HasSecondFactor` was missing SMS. A
companion test was written to keep it honest: ask the database which tables hold
credentials, and fail when the gate does not consult one.

It passed while Duo was an MFA bypass.

The discovery query matched `%otp_credentials` and `totp_credentials`. Duo's
table is `duo_enrollments`. The enrollment table was written, the challenge was
wired up, `HasSecondFactor` was not updated — and the test that existed
precisely to catch that reported success, because it never looked.

A test that fails to look is not a weak test. It is a no-test that reports
success, which is worse than no test at all: the absence of a test is visible.

The rewrite classifies every credential table **explicitly** and checks the list
against the live schema in both directions:

```
core.duo_enrollments holds second-factor credentials and HasSecondFactor does
not consult it. A user whose only factor is in that table signs in with a
password alone, while their account settings say MFA is on.

core.webauthn_credentials is classified as NOT a second factor, but
HasSecondFactor consults it. One of the two is wrong.
```

Broadening the discovery query immediately turned up two more tables nobody had
decided about — `password_credentials` and `recovery_requests` — each of which
now carries a recorded reason for being excluded. A false positive costs one
line; a false negative is an authentication bypass.

**Verified both ways**: with the fix in place the test passes; with Duo removed
from the query it fails, naming the table.
