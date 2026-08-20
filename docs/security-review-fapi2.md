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
