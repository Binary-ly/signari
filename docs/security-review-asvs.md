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
| V10.2.1 | CSRF defence on the code flow (PKCE or `state`) | ✅ both |
| V10.2.2 | Mix-up defence across several authorization servers | ✅ issuer pinned per source; metadata `issuer` compared to the configured one |
| V10.5.1 | ID Token replay — `nonce` | ✅ |
| V10.5.2 | Identify the user by a claim that cannot be reassigned | ✅ `iss`+`sub` pair, never email |
| V10.5.3 | Reject metadata whose issuer does not match | ✅ the same check OID4VCI §12.2.3 and OpenID Federation §9 both state |
| V10.5.4 | ID Token `aud` equals our client id | ✅ |
| V10.5.5 | Back-channel logout: `typ`, and DoS through forced logout | ✅ `logout+jwt` enforced; see V10.6.2 for the provider side |

## V10.3 — resource server

Our userinfo and introspection endpoints are the resource server.

| | Requirement | Verdict |
|---|---|---|
| V10.3.1 | Accept only tokens whose audience is this service | ✅ |
| V10.3.2 | Enforce `sub`, `scope`, `authorization_details` in the decision | ✅ all three — `authorization_details` implemented since this review (RFC 9396) |
| V10.3.3 | Identify the user by a non-reassignable claim | ✅ `sub` is a uuid, never an email |
| V10.3.4 | Enforce `acr`, `amr`, `auth_time` when required | ✅ and re-evaluated per authorization request rather than frozen at sign-in |
| V10.3.5 (L3) | Sender-constrained tokens | ✅ DPoP (RFC 9449) and mTLS (RFC 8705) both |

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
| V10.6.1 | Only `code`, `ciba`, `id_token`, `id_token code`; never `token` | ✅ `response_types_supported` is `["code"]` alone |
| V10.6.2 | **Mitigate denial of service through forced logout** | ❌ → fixed |

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
| V10.7.1 | Consent to each authorization request | ✅ |
| V10.7.2 | Clear information about what is being consented to | ✅ scopes rendered with descriptions |
| V10.7.3 | User can review, modify and revoke granted consents | ✅ the connected-applications screen, which revokes the tokens with the consent |

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
