# Security review: FAPI 2.0 Security Profile

FAPI 2.0 Security Profile, **Final, 22 February 2025** — a general-purpose
high-security profile of OAuth 2.0 that has "been proved by formal analysis to
meet the stated attacker model".


## §5.3.2.1, requirement by requirement

| Requirement | Signari |
|---|---|
| Distribute discovery metadata per OIDD/RFC 8414 | yes |
| Reject the resource owner password credentials grant | yes |
| Only support confidential clients | **profile mode** — we support public clients generally, which a FAPI deployment would disable |
| Only issue sender-constrained access tokens | **profile mode** — supported, not mandatory |
| Sender-constraining via mTLS or DPoP | both implemented |
| Client authentication via mTLS or `private_key_jwt` | both implemented |
| Not expose open redirectors | yes |
| Accept **only** the issuer identifier in a client assertion `aud` | **no** — see below |
| Not use refresh token rotation | **no** — we rotate; see below |
| Authorization codes with a maximum lifetime of 60 seconds | **yes, exactly 60** — and now pinned by `TestTheConstantsAConformanceClaimRestsOnHaveNotDrifted`, since nothing previously stopped the number drifting |
| If using DPoP, support Authorization Code Binding to DPoP Key | **was missing — now implemented** |
| Accept JWT `iat`/`nbf` 0–10s in the future, reject >60s | **was wrong in both directions — now implemented** |

Two rows are deliberate differences rather than gaps. Two were real defects.

## The defect: no authorization code binding to a DPoP key

FAPI 2.0 requires it "if using DPoP", and RFC 9449 §10.1 is blunter about who it
binds:

> **Both mechanisms MUST be supported by an authorization server that supports
> PAR and DPoP.**

Signari supports PAR and supports DPoP, so that MUST applied — and neither
mechanism existed. `dpop_jkt` appeared nowhere in the codebase.

### What it buys that PKCE does not

PKCE binds an authorization code to a secret the client generated. `dpop_jkt`
binds it to the **key the resulting token will be bound to**, which closes the
flow end to end: an authorization code intercepted in the front channel cannot be
redeemed by an attacker's own DPoP key, because the code names the key permitted
to redeem it.

§10 notes they are complementary, and that `dpop_jkt` "only provides similar
protections when a unique DPoP key is used for each authorization request".

### Both mechanisms, because §10.1 requires both

- `dpop_jkt` as an authorization request parameter, and in the PAR POST body.
- A **DPoP header on the PAR request**, in which case the server "MUST further
  behave as if the contained public key's thumbprint was provided using
  dpop_jkt".

Supporting only the first would silently drop the binding for a client that
attaches its DPoP header to every authorization-server request — which is
precisely the client §10.1 exists to accommodate.

And when both are present: "the authorization server MUST reject the request if
the JWK Thumbprint in dpop_jkt does not match the public key in the DPoP header".

### The mistake I made implementing it

The redemption check went in after the PKCE block. That block returns early when
a code carries a challenge — which is every code, since PKCE is required by
default — so the check never ran.

The test caught it on the first execution. Reading the function did not, because
the early return is four lines below where the eye stops. The mutation that moves
the check back to the wrong place is now part of the suite:

| Mutation | Test that caught it |
|---|---|
| Drop the thumbprint comparison | `TestACodeBoundToADPoPKeyIsOnlyRedeemableWithThatKey` |
| Move the check after the PKCE early return | same test |

## The second defect: clock skew, wrong in both directions (August 2026)

Re-checked because the row above said "partial" and nothing in the document said
what the partial part was. An unexplained partial is a gap nobody has looked at.

The requirement is one sentence carrying two opposed obligations:

> "shall accept JWTs with `iat` or `nbf` timestamp between 0 and 10 seconds in
> the future but shall reject greater than 60 seconds"

Both were wrong, in opposite directions:

- **`nbf`** — *any* future value was refused: `now.Before(time.Unix(nbf, 0))`. A
  client whose clock ran two seconds fast could not authenticate at all, and the
  message it got named the assertion rather than the clock. An interoperability
  failure that presents as a signature problem.
- **`iat`** — parsed into the claims struct and **never read**. An assertion
  claiming to be issued an hour in the future was accepted, because the only
  bound on time was `MaxAssertionLifetime`, which measures `exp` against now and
  says nothing about where the window sits. Future-dating does not lengthen the
  window; it moves it.

A third problem fell out of fixing the second: `MaxAssertionLifetime` only bounds
the window *forwards*, so an assertion minted an hour ago with `exp` two minutes
out satisfied it completely — having been a usable credential for that hour.


`JsonWebToken.isActive()` carries the comment:

> "This assumes a default clock-skew for the 'is not before' of 10 seconds which
> is in line FAPI 2.0."


Ten seconds of tolerance rather than sixty. The 10–60 second band is left to the
implementation — "reject greater than 60" does not require accepting 59 — and
every second of tolerance is a second an assertion is usable before its own
client says it should be.

### One of the three fixes was not yet doing anything

Removing the stale-`iat` bound broke no test, while the other two each had one.
A check that cannot be made to fail is not yet known to work, so it got the test
it was missing (`TestAnAssertionIssuedLongAgoIsRefused`) before this was recorded
as done.

`iat` stays OPTIONAL, as RFC 7523 §3 says. Every check is conditional on its
presence, and `TestAnAssertionWithNoIssuedAtStillWorks` pins that.

## The two deliberate differences

**Client assertion audience.** FAPI: "shall only accept its issuer identifier
value... as a string in the `aud` claim received in client authentication
assertions". Ours accepts three values — the issuer, the token endpoint, and the
endpoint being called. That third one was added because a client authenticating
at `/oauth2/par` naturally addresses its assertion to `/oauth2/par`, and refusing
it broke PAR outright.

Every accepted value names this server and nobody else, so the audience check
still does its job. But a FAPI deployment would need the stricter form, and this
is recorded as a mode rather than defended as equivalent.

**Refresh token rotation.** FAPI *prohibits* it; RFC 9700 §2.2.2 *requires*
rotation or sender-constraining for public clients. There is no contradiction —
FAPI mandates sender-constraining, which removes the need — but the two standards
point opposite ways for a server supporting both worlds, and ours follows RFC
9700 by default.

## Currency

Re-verified August 2026 against
<https://openid.net/specs/fapi-security-profile-2_0-final.html>: still **Final,
22 February 2025**, no errata, and §5.3.2.1 still carries the same fourteen
requirements. The profile has not moved; this review's version reference holds.

## Verdict

Two MUST-level defects. The first was also an RFC 9449 §10.1 MUST that had gone
unnoticed through an earlier DPoP review — because that review checked the proof
and the binding at the resource, and never asked what binds the *code*.

The remaining FAPI gaps are profile modes: restrictions a FAPI deployment must
turn on (confidential clients only, sender-constrained tokens only, single
assertion audience), not behaviours that are wrong by default. Making them a
selectable profile is the honest next step, and is not built.

## The requirements this review had not listed (August 2026)

The table above covers §5.3.2.1's authorization-server list. Reading the profile's
section structure rather than working from the existing table showed three groups
missing from it entirely. All were checked against source.

### §5.3.2.1, two rows that were absent

| Requirement | Signari |
|---|---|
| "shall return an `iss` parameter in the authorization response according to [RFC9207]" | **yes** — `authorize.go:324` sets it on every response, and `authorization_response_iss_parameter_supported` is advertised in metadata. This is the mix-up defence from the provider side, and it was implemented without being recorded here |
| "shall reject authorization requests sent without [RFC9126]" | **profile mode** — `require_pushed_authorization` is per client (`par.go:293`), not global. Same standing as the two other profile-mode rows: a FAPI deployment turns it on, a general-purpose one cannot without breaking every client that does not push |

### §5.3.4, the resource server requirements — none were listed

We are a resource server for `/userinfo`, `/introspect` and the credential
endpoint, so all five bind us.


Requirement 2 is the one worth dwelling on: it is a **shall not**, it is the
cheapest of the five to get wrong, and getting it wrong is invisible until
somebody reads an access log. Presenting the token in the header *and* the body
is also rejected rather than resolved by precedence — two token values in one
request is either a broken client or an attempt to have the check read one and
the logic use the other.

## §5.2 and §5.4, the sections this review had not opened

The table above covers §5.3.2.1 and the addendum covers §5.3.4. Two more
normative sections bind a server.

### §5.2 Network layer protections

| Requirement | Signari |
|---|---|
| "shall only offer TLS protected endpoints" | deployment property — the binary serves plaintext behind a terminating proxy, which is the operator's arrangement, not ours to assert |
| "shall set up TLS connections using TLS version 1.2 or later" | Go's default minimum is TLS 1.2; outbound calls use the standard library |
| **§5.2.3: "Servers shall not support CORS for the authorization endpoint"** | **met, and tested** — `oidc.PathAuthorize` is deliberately absent from the CORS allow-list with a comment saying it must stay absent, and `TestTheAuthorizationEndpointNeverGetsCORS` holds it there. The same prohibition appears as RFC 9700 §2.6, which is where our comment cites it |

The CORS rule is the one worth dwelling on: the authorization endpoint is reached
by **navigation**, never by `fetch`. Any script that can read its response is
reading a page that may already carry an authorization code.

### §5.4 Cryptography and secrets

| Requirement | Signari |
|---|---|
| "RSA keys shall have a minimum length of 2048 bits" | met — `rsa.GenerateKey(rand.Reader, 2048)` |
| "Elliptic curve keys shall have a minimum length of 224 bits" | met — ES256 is P-256 |
| "not use or accept the `none` algorithm" | met — every verifier parses with an asymmetric allow-list; `none` is absent everywhere |
| §5.4.2 "shall only serve the `jwks_uri` endpoint over TLS" | deployment property, as above |
| §5.4.2 "should not use the JOSE headers for `x5u` and `jku`" | met — both refused explicitly in `verifiedPayload`, alongside an embedded `jwk` |
| §5.4.2 "should not serve a JWK set with multiple keys with the same `kid`" | met **structurally** — `keys.NewSet` refuses to construct a set with a duplicate `kid` at all, so an offending set cannot be served because it cannot exist |
| **"use PS256, ES256, or EdDSA (using the Ed25519 variant) algorithms"** | **profile mode** — see below |

### The one that is profile mode, and was not previously listed

FAPI's algorithm list is `PS256`, `ES256`, `EdDSA`. **RS256 is not on it.**

We sign with ES256 by default and support PS256 and EdDSA, all three of which
qualify. But `RS256` is also a supported signing algorithm, and
`clientauth.allowedAlgs` accepts `RS256`/`RS384`/`RS512` for `private_key_jwt`
assertions. A FAPI deployment must not use or accept those.

That puts §5.4.1 in the same category as the three profile-mode rows already in
the table above — public clients, mandatory sender-constraining, and global PAR:
capabilities a FAPI deployment turns off rather than defaults we get wrong. It
was simply never listed, which is the difference between a deviation somebody
chose and one nobody noticed.

**What it would take:** the algorithm allow-lists are constants, and narrowing
them is a one-line change per site. What is not one line is deciding whether to
narrow them globally — which breaks every existing RS256 client — or per client,
which needs a registration attribute and a migration. Recorded rather than
changed, for the same reason as the other three.

## §5.4.1 key strength: the floor was not enforced (20 August 2026)

Reviewed against **FAPI 2.0 Security Profile, Final, 22 February 2025**, with
every normative keyword extracted by section — 92 uses, densest at §5.3.2.2
(16), §5.3.2.1 (15) and §5.3.3.1 (15).

> "RSA keys shall have a minimum length of 2048 bits."
> "Elliptic curve keys shall have a minimum length of 224 bits."

Nothing enforced this on a client's registered JWKS. A client could register a
**1024-bit RSA public key** and authenticate with `private_key_jwt` indefinitely —
a key below every recognised floor since NIST withdrew 1024-bit RSA in 2013, and
one a well-resourced attacker can factor.

The client is the party harmed, which is precisely why the authorization server
has to be the one checking: the client that registers a weak key is the client
least likely to notice.

It was also an inconsistency inside one codebase rather than a considered
position. The same floor was already enforced on SAML encryption certificates
(`internal/saml/encrypt.go:107`) and on certificate import in the CLI. Only the
path that authenticates clients was missing it.

**Enforced against the key that actually verified**, not by filtering the
registered set up front. A client mid-rotation with one strong key and one legacy
weak key keeps working on the strong one; a client that signed with the weak one
gets an error naming the key type and the bit length, rather than the "no
registered key verified it" message that would send an integrator to the wrong
place.

Elliptic curve keys need no separate gate in practice — `jose.ParseSigned` pins
the algorithm list, and P-256 upward all clear 224 bits — but the check is
written for both so the floor does not depend on that coincidence holding.

### §5.4.3, Handling Duplicate Key Identifiers — already satisfied

> "when there are multiple keys with the same `kid`, the verifier shall consider
> other JWK attributes, such as `kty`, `use`, `alg`, etc., when selecting the
> verification key"

Our verifiers iterate candidate keys and attempt verification rather than
committing to the first `kid` match, which is a strictly stronger selector than
comparing `alg`: a key that produces a valid signature is the key that signed it.
`internal/ssf/receive.go` filters on `kid` and then tries each match;
`internal/clientauth/privatekeyjwt.go` tries every registered key. Both terminate
on a verified signature, so a duplicate `kid` cannot cause a false rejection.

## §5.3.2.2's 303: did anyone try it and revert? (21 August 2026)

We converted 46 redirect sites from `302` to `303` for one SHOULD:

> "should use the HTTP 303 status code when redirecting the user agent"


```
OIDCRedirectUriBuilder$QueryRedirectUriBuilder     sipush 302 → Response.status(I)
OIDCRedirectUriBuilder$FragmentRedirectUriBuilder  sipush 302 → Response.status(I)
OIDCRedirectUriBuilder$JWTRedirectUriBuilder       sipush 302 → Response.status(I)
OIDCRedirectUriBuilder$FormPostRedirectUriBuilder  Status.OK  → an HTML form
```


```python
class HttpResponseRedirectScheme(HttpResponseRedirect):
    """HTTP Response to redirect, can be to a non-http scheme"""
```

No `status_code` override anywhere in the module, so it inherits Django's
**302**.


### The finding: it is not that 303 is wrong, it is that it breaks passivity

The strongest evidence is from a third implementation. **Spring Authorization
Server #1051** and **Spring Security #18264** both ask for exactly this change,
citing *A Comprehensive Formal Security Analysis of OAuth 2.0* — the paper that
first described the 307 credential-leak attack, and the reason FAPI writes this
requirement at all.

Both issues are **open**. Both carry the label `type: breaks-passivity`, Spring's
term for a change that alters behaviour relying parties may depend on.

That is the real answer to "why doesn't anyone do this". Not that the SHOULD is
wrong, not that it was tried and reverted — but that changing the status code of
an authorization response in a mature server is a compatibility event, and
mature servers defer compatibility events. We have no installed base to break, so
the cost that stops them does not apply to us. That is a better reason to be
ahead than "we read the specification and they did not", and it is the one
supported by evidence.

### The counter-evidence, weighed rather than omitted

One report exists of 303 breaking an OAuth flow: a Hugging Face forum thread
(February 2024) where an authorization endpoint returning 303 was blamed for "the
loss of the original window object", so a popup-based client could not
programmatically close its auth tab. Libraries like `react-use-oauth2` are named.

Assessed as most likely a misattribution, and the reasoning is recorded so
somebody can disagree with it:

- A redirect status code does not sever `window.opener`. Ordinary cross-origin
  navigation does not either. The mechanism that *does* is
  `Cross-Origin-Opener-Policy` — which is why this engine deliberately does not
  set it, for this same population of relying parties (see
  `security-review-asvs.md`, V3.4.8).
- The symptom described — a parent unable to read or control the popup — is what
  happens when a script reads `popup.location.search` across origins, which
  throws regardless of status code.
- The thread is an unresolved user report, not a maintainer diagnosis, and no
  follow-up establishes cause.

It is possible and unproven. What makes it low risk for us specifically is that
303 differs from 302 in exactly one respect: it *requires* the method to become
GET, where 302 merely permits it. Every redirect this engine emits after a POST
targets a handler that expects a GET, so the coercion 303 forces is the behaviour
we already relied on 302 to choose.

### Verdict


Nobody tried our way and reverted. Two of the three have not tried; the third
wants to and is blocked by backward compatibility rather than by a defect. Ours
is better here, and now for a reason that was checked instead of assumed.

## Second turn: normative extraction, and the trap it started with (21 August 2026)

The first pass read the profile section by section. This is a different method on
the same document — extract every normative keyword mechanically, enumerate the
requirements, and check them one at a time.

### The extraction found zero requirements, and that was the finding

An RFC 2119 extraction over this specification returns **nothing**. Not "few" —
zero MUST, zero SHALL, zero SHOULD.

FAPI 2.0 does not use RFC 2119. Its own notational conventions say so:

> The keywords "shall", "shall not", "should", "should not", "may", and "can" in
> this document are to be interpreted as described in **ISO Directive Part 2**.

**Lowercase.** An uppercase-only sweep — the one that works on every RFC and
every OpenID Foundation specification reviewed in this repository — silently
reports a security profile as containing no requirements at all.

Recorded because it is the fourth false negative from a search in this review
cycle, and the most dangerous shape of one: not "the grep missed a file" but "the
grep returned a clean, plausible, completely wrong zero". The earlier
section-by-section pass was unaffected, because a human reading prose does not
care about case — which is the argument for not replacing reading with tooling.

Re-run with ISO keywords: **94 normative uses, 67 distinct "shall" sentences, 25
of them naming the authorization server.**

### The requirement I nearly reported as a gap

> "if using DPoP, shall support the server provided nonce mechanism (as defined
> in Section 8 of [RFC9449])"


It is not. The bullet sits under **§5.3.3, "Requirements for clients"**, in a list
beginning "Clients ¶ shall support sender-constrained access tokens...". It
requires a FAPI *client* to handle a `use_dpop_nonce` challenge. It places no
obligation on the authorization server to issue one.

Checked by pulling 2,200 characters of preceding context rather than trusting the
sentence in isolation. A requirement extracted without its heading is a
requirement whose subject is unknown.

### Four server requirements checked concretely

| §5.3.2 requirement | Signari |
|---|---|
| "shall not use the HTTP 307 status code when redirecting a request that contains user credentials" | never used; `responsemode.go` cites the rule and uses 303 |
| "shall issue authorization codes with a maximum lifetime of 60 seconds" | `codeTTL = 60s` — exactly at the ceiling |
| "shall issue ... `request_uri` with `expires_in` values of less than 600 seconds" | `parLifetime` = 90s |
| "shall support `nonce` parameter values up to 64 characters in length" | no length bound, so any length is accepted |

The two lifetime ceilings were met by constants that **did not know they were
FAPI requirements**. `codeTTL`'s comment reads "RFC 6749 recommends <= 10 minutes;
short is free here" — true of RFC 6749, and one edit away from a silent
conformance break by somebody taking the RFC at its word.

`TestFAPILifetimeCeilingsHold` now connects the constants to the profile. The
mutation that raises `codeTTL` to RFC 6749's allowance fails it with the profile
quoted.

```
CAUGHT   raise codeTTL to RFC 6749's 10 minutes (FAPI §5.3.2.2 caps it at 60s)
```

### Scope, stated so the test is read correctly

FAPI is a profile a deployment opts into. Most of §5.3.2 is *restrictions* —
confidential clients only, PAR mandatory, sender-constrained tokens only — that a
general-purpose IdP correctly does not apply by default, and those remain profile
modes rather than defects. The two lifetime rules are different in kind: ceilings
we already sit under, where holding them costs nothing and losing them would be
invisible.
