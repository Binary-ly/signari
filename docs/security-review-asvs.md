# OWASP ASVS 5.0 — the OAuth, OIDC and token chapters, requirement by requirement

**OWASP Application Security Verification Standard 5.0.0**, released 30 May 2025,
confirmed current from the project's own release list (the `latest` tag is a
bleeding-edge build, not a release). Requirements taken from the published CSV,
not from a summary.

ASVS 5.0 introduced a **new chapter, V10 "OAuth and OIDC"** — 36 requirements —
which is the first time this standard has covered an authorization server
directly. Together with V9 "Self-contained Tokens" (7) that is 43 requirements
aimed squarely at what this product is.

This file walks every one of them. Signari is an **authorization server and
OpenID Provider**, and is also an **OIDC client** for social login and inbound
federation, so both sides apply. The OAuth-client sections apply only to that
inbound path.

## The finding

**One requirement was not met: V10.6.2.** Everything else in the applicable
sections was already satisfied, several by a stronger mechanism than the
requirement asks for. Details below, then the gap.

## V9 — Self-contained Tokens

Re-verified against source in August 2026, one requirement at a time. The
verdict column says where the check actually is, so a reader can disagree with
it rather than take a tick on trust.

| | Requirement | Verdict |
|---|---|---|
| V9.1.1 | Validate signature before accepting contents | ✅ `verifiedPayload` returns the payload only after `tok.Verify`; every caller unmarshals from that return value, so no path reads claims first |
| V9.1.2 | Algorithm allowlist, no `none`, no symmetric/asymmetric confusion | ✅ the list is `RS256, ES256, PS256, EdDSA` — asymmetric only, `none` absent. The check that matters is the next one: `if string(key.Algorithm()) != h.Algorithm` pins the algorithm to the **key's** declared one rather than the header's, which is what actually defeats alg confusion; an allow-list alone does not |
| V9.1.3 | Key material from pre-configured sources; reject `jku`, `x5u`, `jwk` | ✅ refused explicitly, and tested (`TestATokenCannotSupplyItsOwnKey`) |
| V9.2.1 | Honour `nbf`/`exp` | ✅ **`exp` fail-closed** — `c.Expiry == 0` is treated as expired, not as absent. **`nbf` is checked exactly where externally-minted JWTs arrive**: `private_key_jwt` client assertions (`privatekeyjwt.go:204`, bounded by `MaxClockSkew`). Our own access tokens carry no `nbf`, so there is nothing to honour there. On the SSF receive path `exp` is not merely checked but **forbidden**, per SSF §4.1.7 |
| V9.2.2 | Validate token **type** and purpose | ✅ checked inside the shared verifier against a value the caller names, so a single-purpose token cannot be presented elsewhere — `at+jwt`, `secevent+jwt`, `logout+jwt` |
| V9.2.3 | Accept only tokens whose audience is this service | ✅, and the **issuer** check beside it is now tested too — it had survived mutation against the whole suite, and on this server aliased issuers share a key set, so `iss` is the only thing separating them |
| V9.2.4 | Audience restriction when one key serves several audiences | ✅ `audience := []string{c.ClientID}; if len(resources) > 0 { audience = resources }` — RFC 8707 resources become the audience, the client id the fallback only when none were requested |

## V10.1 / V10.2 / V10.5 — client-side

V10.2 (OAuth Client) and V10.5 (OIDC Client) apply to inbound social login and
federation, where Signari is the relying party.

| | Requirement | Verdict |
|---|---|---|
| V10.2.1 | CSRF defence on the code flow (PKCE or `state`) | ✅ both, and the `state` half is **now tested** — nothing referenced `ConsumeFederatedLogin` or `core.federated_logins` before. Single-use (`DELETE … RETURNING`), bound to the originating browser by a cookie hash compared in constant time, and — the subtle part — the comparison happens **after** the row is destroyed, so a wrong binding still burns the state rather than leaving it to be ground against. All three tested; dropping the binding comparison fails the second |
| V10.2.2 | Mix-up defence across several authorization servers | ✅ `discovery.go:60` — `strings.TrimSuffix(d.Issuer,"/") != strings.TrimSuffix(issuer,"/")` refuses a discovery document that declares an issuer other than the one asked for (RFC 8414 §3.3), and the id_token's `iss` is compared to the configured issuer again at `client.go:252` |
| V10.5.1 | ID Token replay — `nonce` | ✅ generated per login with `randomToken()` and stored on the pending record, so the empty-nonce path in `verifyIDToken` is unreachable from the live flow. Both directions tested: `TestIDTokenAttacks` covers **"nonce from a different login (replay)"** and **"no nonce at all"** |
| V10.5.2 | Identify the user by a claim that cannot be reassigned | ✅ the external identity is keyed `UNIQUE (provider_id, subject)` (migration 0022), so it is the issuer-and-subject pair rather than an address. An email is reassignable — a departed employee's address handed to their replacement would otherwise take over the account |
| V10.5.3 | Reject metadata whose issuer does not match | ✅ `discovery.go:60`, the same check OID4VCI §12.2.3 and OpenID Federation §9 both state |
| V10.5.4 | ID Token `aud` equals our client id | ✅ `audienceContains` handles both the string and array forms, and `TestAudienceArrayIsHandled` plus the "audience is a different application" attack case cover it |
| V10.5.5 | Back-channel logout: `typ`, and DoS through forced logout | **provider side yes; client side not implemented.** We *send* logout tokens explicitly typed `logout+jwt` (asserted in `outbox/logouttoken_test.go`) and the forced-logout DoS is handled at V10.6.2. We do **not** receive OIDC back-channel logout from upstream federation providers — there is no such route. The equivalent need is met by a different mechanism: `/ssf/receive` accepts CAEP `session-revoked`, which ends the local session. Recorded as a boundary rather than a tick, because a ✅ here would claim a receiver we do not have |

## V10.3 — resource server

Our userinfo and introspection endpoints are the resource server.

| | Requirement | Verdict |
|---|---|---|
| V10.3.1 | Accept only tokens whose audience is this service | ✅ `AudienceAccepted` gates `/userinfo` and the credential endpoint. Verified by mutation against the **whole** suite: making it return true unconditionally fails `TestATokenForAnotherResourceIsRefused` and `TestAudienceRestrictionIsEnforcedAgainstOurselves` |
| V10.3.2 | Enforce `sub`, `scope`, `authorization_details` in the decision | ✅ all three. The **scope** half is now tested at `/oauth2/userinfo`, and it needed to be: the handler gates `email`, `profile` and `groups` individually, and no test varied the scope — so nothing established that a claim is actually **withheld**. A test asking for everything and receiving everything passes identically against a handler that ignores scope; only asking for less proves the difference. Releasing `email` unconditionally now fails `TestUserinfoWithholdsClaimsTheScopeDidNotGrant` |
| V10.3.3 | Identify the user by a non-reassignable claim | ✅ `sub` is `core.users.id`, a `uuid NOT NULL DEFAULT gen_random_uuid()` — verified in the schema, not inferred from the code that reads it |
| V10.3.4 | Enforce `acr`, `amr`, `auth_time` when required | ✅ `ACRFromAMR` derives the context from the factors **actually used**, and `FlowDemandsMFA` is consulted per authorization request rather than frozen at sign-in — a live password-only session is stepped up when `acr_values` demands it |
| V10.3.5 (L3) | Sender-constrained tokens | ✅ both, with 7 tests across `dpoprefresh_test.go` and `mtlsrefresh_test.go` covering the bound key refusing a different key, refusing no proof at all, and still working with the right one |

## V10.4 — authorization server, the core


### V10.4.2, and the half a sequential test cannot reach

The requirement was met and the revocation was properly tested:
`TestCodeReuseRevokesTheIssuedTokens` replays the code and then reads
`core.refresh_token_families` to confirm `revoked_at` is set.

What no test reached was **concurrency**. A stolen authorization code races the
legitimate client by construction — both hold it at the same moment — and a
sequential "redeem twice" passes even against an implementation that reads the
row, decides it is unspent, and updates it afterwards, because the window between
the two is never open.

Rewriting `ConsumeCode` from

```sql
UPDATE core.authorization_codes SET consumed_at = now()
WHERE code_hash = $1 AND consumed_at IS NULL RETURNING ...
```

into a `SELECT` followed by an `UPDATE` makes
`TestConcurrentRedemptionOfOneAuthorizationCodeYieldsOneTokenSet` report **8 of 8
simultaneous redemptions received tokens** — while every pre-existing test,
including the revocation one above, still passes. A racy implementation would
have shipped through the suite unnoticed.

Two tests now pin it: eight goroutines released together against one code over
three rounds, and a behavioural check that the refresh token is exercised
*before* the replay and its rotated successor refused *after*, so revocation is
measured by the refresh grant being denied rather than by a column being set.

### V10.4.8, and why it is met by something better than a cap

The requirement is *"refresh tokens have an absolute expiration, including if
sliding refresh token expiration is applied"*.

Rotation mints a new token with a fresh expiry, so the **token-level** deadline
does slide. What does not slide is `sessions.not_after`: it is fixed when the
session is created and updated **nowhere** in the codebase — verified by
searching, not assumed. `RotateRefreshToken` requires that session to be live:

```sql
AND (s.sid IS NULL OR (s.revoked_at IS NULL AND s.not_after > now()))
```

So a lineage cannot outlive the sign-in that authorized it, however many times it
rotates. That is a stronger property than a cap on the credential, because it
expires the **authorization** rather than the token representing it.

But read that SQL again: `s.sid IS NULL OR …`. A family with no session is
vacuously live forever. No caller created one — which is a fact about the code as
it stands, not about the code as it will be. `NewRefreshFamily` now refuses an
empty `sid`, and `TestARefreshFamilyMustNameASession` keeps it that way.

## V10.6 — OpenID Provider, and the requirement that was not met

| | Requirement | Verdict |
|---|---|---|
| V10.6.1 | Only `code`, `ciba`, `id_token`, `id_token code`; never `token` | ✅ `response_types_supported` is `["code"]` alone, and the authorize endpoint refuses anything containing `token` outright — an access token must never cross the front channel |
| V10.6.2 | **Mitigate denial of service through forced logout** | ❌ → fixed, and tested. The distinction that carries it is *verified* versus *present*: `logoutconfirm_test.go` asserts an **unverified** `id_token_hint` does not skip the confirmation, which is the case that would otherwise reintroduce the attack through the parameter meant to prevent it |

V10.6.2, verbatim:

> Verify that the OpenID Provider mitigates denial of service through forced
> logout. By obtaining explicit confirmation from the end-user or, if present,
> validating parameters in the logout request (initiated by the relying party),
> such as the `id_token_hint`.

OIDC RP-Initiated Logout 1.0 §2 says the same from the other side: the OP
*"SHOULD ask the End-User whether to log out"* unless the request carries a valid
`id_token_hint`.

**We did neither.** `GET /oauth2/logout` terminated the session in the caller's
cookie unconditionally. `id_token_hint` was parsed, but only to resolve which
client's `post_logout_redirect_uri` list to check — a request with no redirect
never looked at it.

The attack is one HTML tag:

```html
<img src="https://id.example.com/oauth2/logout">
```

on any page the victim visits. They are signed out, as often as the page loads,
from anywhere. Nothing is stolen; the product simply stops staying signed in, and
a user cannot tell that from a bug.

**Fixed.** A logout now proceeds without asking only when one of three things is
true: the request is a `POST` carrying a valid CSRF token (the person confirmed),
or it carries an `id_token_hint` that **verifies** (a relying party asked, which
is what the specification accepts in place of asking), or there is no session
cookie at all (nothing to end). Otherwise a confirmation page is rendered and
nothing is terminated.

The form POSTs back to the request URI, so `post_logout_redirect_uri`, `state`
and `client_id` survive the round trip and are validated exactly as before.

The distinction between *present* and *verified* is the whole of it: an
unverified `id_token_hint` is a string the attacker chose, and accepting one
would reintroduce the attack through the parameter meant to prevent it.
`TestAnUnverifiedIDTokenHintDoesNotSkipConfirmation` exists for that reason.

## V10.7 — consent

| | Requirement | Verdict |
|---|---|---|
| V10.7.1 | Consent to each authorization request | ✅ and the hard case is covered: `authorization_details` **always** prompt, which neither stored consent nor the first-party exemption can bypass — a user who approved the scope `payments` approved a capability, never a payment. `TestAuthorizationDetailsAlwaysPromptEvenForAFirstPartyClient` |
| V10.7.2 | Clear information about what is being consented to | ✅ `scopeDescriptions` maps each scope to a human sentence and the screen renders `{Name, Description}` pairs, so a person is not asked to approve the string `groups` |
| V10.7.3 | User can review, modify and revoke granted consents | ✅ the connected-applications screen, which revokes the tokens with the consent — **now tested**, and it needed to be. `WithdrawConsent` deliberately does *not* touch tokens; only `DisconnectApp` does both, in one transaction. So the requirement is met by one caller choosing the right function, and a future handler reaching for the obvious-sounding `WithdrawConsent` would keep the screen working and lose the property silently |

## What this sweep leaves open

- ~~**`authorization_details` (RFC 9396)** is not implemented~~ — **done**, which
  closed V10.3.2 and V10.4.15. See
  [rich-authorization-requests.md](rich-authorization-requests.md).
- **V10.4.13 and V10.4.14** are L3 requirements met as capabilities rather than
  as mandates. Making PAR and sender-constrained tokens compulsory for every
  client is a deployment decision, not a code change, and forcing it would break
  every client that does not do them yet.

Neither is a defect. Both are recorded because "not met at L3" and "not met" read
identically in a table that does not say which.


---

# Currency check, August 2026

ASVS 5.0.0 (30 May 2025) is still the **current stable release**. Verified rather
than assumed: the OWASP/ASVS repository carries a release tagged `latest`
published **28 July 2026**, which is newer than 5.0.0 and easy to mistake for a
successor. It is not one — it is an automatically regenerated *bleeding edge*
build from `master`, and its own release notes say so:

> "This bleeding-edge version represents the most current state of the ASVS
> documentation and should be used for testing and preview purposes only. For
> production use, please refer to the stable releases (The latest stable release
> is v5.0.0)."

Downloading its CSV and diffing against the 5.0.0 CSV this review was written
against gives **zero differing lines**. V10 "OAuth and OIDC" still has exactly 36
requirements, unchanged.

So this review is current, and the check cost one download. Worth repeating
before trusting it again — the failure mode being guarded against is a review
that was accurate when written and quietly stops being so.

## V9 Self-contained Tokens: all seven, swept completely (21 August 2026)

The ASVS 5.0.0 requirement set was downloaded and enumerated rather than
recalled — **345 requirements across 17 chapters**. V9 is seven of them, small
enough to check *every one* rather than sample, which is what a systematic sweep
has to mean.

| Requirement | Status |
|---|---|
| **V9.1.1** signature validated before contents are accepted | met — `verifiedPayload` returns the payload only after `tok.Verify`, and no caller can reach claims another way |
| **V9.1.2** algorithm allowlist, no `None` | met, and now guarded — see below |
| **V9.1.3** key material only from pre-configured sources; `jku`/`x5u`/`jwk` validated | **exceeded** — those headers are refused outright rather than allowlisted |
| **V9.2.1** validity span honoured (`nbf` and `exp`) | **was partial** — fixed, see below |
| **V9.2.2** correct token type for the purpose | met structurally — every verification passes an expected `typ`, so there is no code path that reads claims without one |
| **V9.2.3** audience checked against an allowlist | met |
| **V9.2.4** audience restriction uniquely identifies the audience | met — RFC 8707 resources become `aud`, validated because they do |

### V9.1.2, turned from a review into a standing check

This engine parses signed tokens in eight places: access tokens, ID tokens, DPoP
proofs, SSF events, federation trust chains, upstream OIDC, Apple client secrets,
`private_key_jwt`, ABCA attestations. Each passes its own allowlist to
`jose.ParseSigned`, which is the right shape — the library makes the list
mandatory, so it cannot be forgotten.

What that shape cannot prevent is a future edit adding `jose.HS256` to one of the
eight "so the test client works". A reviewer looking at that file sees a
plausible list. Nobody looks at all eight at once.

`TestNoTokenVerifierAcceptsNoneOrHMAC` does, and it fails naming the file and
line — verified by planting `jose.HS256` in the DPoP allowlist:

```
1 token verifier(s) admit 'none' or an HMAC algorithm:
  engine/internal/dpop/dpop.go:73: jose.HS256,
```

It also refuses to pass if it finds fewer than five `ParseSigned` sites, so it
cannot succeed by walking the wrong directory — the failure mode that once let a
mutation harness report eight covered guards as uncovered.

**Asymmetric-only everywhere is stronger than V9.1.2 asks.** The requirement
allows both families with "additional controls... to prevent key confusion". With
no symmetric algorithm in any verifier, that attack cannot be constructed here:
there is no context in which a public key could be presented as an HMAC secret,
because nothing will accept an HMAC.

### V9.2.1: the gap, and why it hid

`internal/federation/client.go` validated `iss`, `aud`, `exp` and `nonce` on an
upstream ID token — and not `nbf`.

> "Verify that, if a validity time span is present in the token data, the token
> and its content are accepted only if the verification time is within this
> validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be
> verified."

An upstream that said "not valid before T" was honoured before T.

**It hid because we never emit `nbf`.** Every token this code was written against
and tested with lacked one, so nothing exercised the missing branch and nothing
looked absent. The claim only arrives from somebody else's issuer — which is
precisely the direction this file faces.

Fixed, with `iat` bounded in the same direction and by the same ten seconds
`clientauth` allows for FAPI 2.0 §5.3.2.1. Both cases are now in
`TestIDTokenAttacks` beside "expired", "no expiry at all" and "alg none", and the
`nbf` case was kill-checked.

### Chapter coverage after this pass

V9 complete (7/7). V10 OAuth and OIDC was swept earlier at 41 of 43 evidenced.
V6 Authentication (47), V7 Session Management (19), V8 Authorization (13) and
V11 Cryptography (24) have partial coverage from the protocol reviews but no
requirement-by-requirement sweep — recorded in TODO-FOR-YOU.md as open rather
than claimed.
