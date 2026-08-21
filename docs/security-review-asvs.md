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

## V7 Session Management: nineteen requirements, one gap (21 August 2026)

| Requirement | Status |
|---|---|
| **V7.2.1** verification on a trusted backend | met — the cookie is a reference token resolved against the database on every request |
| **V7.2.2** dynamically generated, not static secrets | met |
| **V7.2.3** CSPRNG, ≥128 bits | **exceeded** — `newSID` is 32 bytes from `crypto/rand`, 256 bits, and the sid and cookie token are two independent values |
| **V7.2.4** new token on authentication **and the current one terminated** | **was half met** — fixed, below |
| **V7.4.1** termination disallows further use | met — every lookup filters `revoked_at IS NULL` |
| **V7.4.2** all sessions terminated when an account is disabled | **exceeded** — session lookups join `u.status = 'active'`, so disabling a user kills every session *instantly*, with no sweep and no window |
| **V7.4.3** option to end other sessions after a factor changes | partial — `ReasonPasswordChange` and `ReasonMFAReset` exist and terminate; the user-facing *option* does not |
| **V7.4.5** administrators can terminate sessions | met — `ReasonAdminRevoke` |
| **V7.3.1** inactivity timeout | **not met** — item 9f, unchanged |
| **V7.3.2** absolute maximum lifetime | met — `not_after`, enforced in every lookup as well as by the sweep |
| **V7.5.2** users can view and terminate their sessions | partial — the data exists; the page does not |
| **V7.1.1–7.1.3** documentation of timeouts, concurrency, federation | partial — timeouts and deviations are documented here and in TODO-FOR-YOU.md; concurrent-session policy is not |

### V7.2.4: the half that was missing

> "Verify that the application generates a new session token on user
> authentication, **including re-authentication**, and terminates the current
> session token."

`completeSignIn` mints a fresh sid and cookie token every time, so session
fixation has never worked here. The previous session row, however, stayed live
until `not_after`.

**Step-up is where that bites.** Someone signs in with a password (`acr=1`),
something asks for another factor, they re-authenticate, and they now hold an
`acr=2` session. The `acr=1` session remained valid for hours — so anyone holding
that earlier cookie kept a working password-only session. And step-up is usually
prompted *because* something looked wrong, which makes the stale session the one
an attacker is most likely to be holding.

Now terminated in the same transaction that creates the replacement, so the old
session dies exactly when the new one is born and a crash between the two cannot
leave both live. It goes through `TerminateSessions` rather than an `UPDATE`,
which means the CAEP `session-revoked` notices are queued too: relying parties
holding tokens from the old session learn it ended instead of discovering it at
expiry.

**Scoped to the session this browser presented**, not to the user. Someone signed
in on a phone and a laptop who re-authenticates on the laptop has not asked to be
signed out of the phone — that would be a defensible product decision and a
different one, and it would turn every step-up into a global sign-out. There is a
test for each direction.

A new `reauthenticated` termination reason rather than reusing `logout`: an
operator reading the audit trail should be able to tell a session that ended
because somebody left from one that ended because it was superseded, and the
value travels to relying parties in the CAEP event.

### What V7 leaves open

V7.3.1 (inactivity timeout) is item **9f** and unchanged. V7.4.3 and V7.5.2 both
describe a *page* — "give the option to terminate all other sessions", "users are
able to view and terminate active sessions" — and the mechanism behind both
already exists and is used by the admin path. What is missing is the screen, which
is the same shape as **9k**. Recorded rather than built, because a session-list UI
is a product surface and you have not asked for one.

## V8 Authorization: the tenant boundary, audited by enumeration (21 August 2026)

V8.4.1 — "multi-tenant applications use cross-tenant controls to ensure consumer
operations will never affect tenants with which they do not have permissions to
interact" — is checkable by enumeration rather than reading, because the boundary
is in the schema.

Querying `pg_class` for every `core` table carrying `org_id` found **58 tables**,
of which **18 did not enforce isolation**:

- **11 with no row-level security at all** — `audit_events`,
  `credential_configurations`, `credential_nonces`, `preauthorized_codes`,
  `rac_sessions`, `duo_enrollments`, `duo_challenges`, `client_attesters`,
  `attestation_challenges`, `authorization_detail_types`,
  `client_authorization_detail_types`
- **7 with a policy but no FORCE** — `relations`, `authorization_models`,
  `impersonations`, `event_deliveries`, `event_subscriptions`, `ssf_received`,
  `ssf_sources`

The FORCE half is the subtle one. Core tables are owned by `signari_engine`, and
**PostgreSQL exempts a table's owner from its own policies unless FORCE is set**.
So those seven carried a policy that read as protection and did nothing for the
engine — not by decision, but by a database default.

### A claim I made and had to withdraw

The first version of this finding said the console could reach other tenants'
rows in the eleven unprotected tables. **That was wrong.** Checking the roles
instead of assuming them shows why:

| Role | Reaches `core` | BYPASSRLS | Login |
|---|---|---|---|
| `signari_admin` (the Laravel console) | **no grants at all** — 15 views in `core_v1` | no | yes |
| `signari_maintenance` | full DML | **yes**, deliberately | **no** — `SET ROLE` only |
| `signari_engine` | owner | no | yes |

The console cannot touch a core table with or without RLS. `signari_maintenance`
is exempt on purpose, and migration 0003 says so in as many words: "Cross-org
maintenance (key rotation, expiry sweeps, the bootstrap CLI) runs as
signari_maintenance." It is `NOLOGIN`, so it is reachable only by an explicit
`SET ROLE`.

So **no role that connects today was crossing tenants, and none could have.** The
finding is real and its severity is not what I first wrote. It is worth recording
the correction rather than quietly restating the smaller claim, because the
error was the same one this session has caught three times elsewhere — asserting
what a component does without reading the component.

### What the fix is actually worth

Uniformity. Fifty-eight org-scoped tables now behave identically; `is_engine()`
is the single visible escape rather than one escape plus a silent ownership
default; and a role added later inherits the boundary instead of inheriting
eleven exceptions nobody remembers.

`TestEveryOrgScopedTableEnforcesTenantIsolation` keeps it that way, and the
reason it earns its place is that **the eighteen exceptions were never
decisions**. A table gets created, its migration does not copy the four lines the
other fifty-seven carry, and nothing notices. The test notices and names the
table — verified by dropping FORCE from `relations`:

```
relations: enabled but not FORCEd, so the owning role (signari_engine)
bypasses the policy silently
```

It also refuses to pass if it finds fewer than 40 org-scoped tables, so it cannot
succeed by querying the wrong schema.

### The rest of V8

| Requirement | Status |
|---|---|
| **V8.2.1** function-level access restricted to explicit permissions | met — `Principal.Can`, and every admin route checks a scope |
| **V8.2.2** data-specific access, IDOR/BOLA | met — `MayActOn` on both the create path and the update path, which the comment there notes is the whole point: "a boundary that holds for creates and not for edits is worse than no boundary" |
| **V8.3.1** enforced at a trusted service layer | met |
| **V8.3.3** decisions use the originating subject's permissions | met — RFC 8693 `act` chains the actor rather than replacing the subject |
| **V8.4.1** cross-tenant controls | met, and now uniform |
| **V8.1.x** documentation of the rules | partial — the rules are in code comments and these reviews rather than in one document |
| **V8.2.3** field-level (BOPLA) | partial — SCIM releases a fixed attribute set; there is no per-field permission model |
| **V8.2.4 / V8.4.2** adaptive controls, layered admin access | partial — the policy engine evaluates device posture and impossible travel; it is not applied to the admin interface specifically |

## V11 Cryptography: twenty-four requirements (21 August 2026)

| Requirement | Status |
|---|---|
| **V11.2.1** industry-validated implementations | met — Go's standard library and `x/crypto`; no hand-rolled primitives |
| **V11.2.3** minimum 128 bits of security | **was not met for generated RSA keys** — fixed, below |
| **V11.2.4** constant-time comparison | met — `subtle.ConstantTimeCompare` on every secret comparison, and `hmac.Equal` where a MAC is compared |
| **V11.3.1** no insecure block modes or weak padding | met for encryption — AES-GCM everywhere, RSA-OAEP for SAML key transport. See the RS256 note below |
| **V11.3.2** approved ciphers such as AES-GCM | met — `cipher.NewGCM` in `keys/store.go`, `keys/subject.go`, `saml/encrypt.go` |
| **V11.3.3** encrypted data protected against modification | met — GCM is authenticated encryption, so this is the same fact as V11.3.2 |
| **V11.4.1** approved hash functions; no MD5 | met, with three protocol-mandated exceptions, below |
| **V11.4.2** password hashing with an approved KDF | met — Argon2id |
| **V11.4.3** collision-resistant hashes ≥256 bits for signatures | met — SHA-256 and above throughout; SHA-1 refused on inbound SAML |
| **V11.5.1** CSPRNG, ≥128 bits of entropy | **exceeded** — `crypto/rand`, 256 bits for session and device codes |
| **V11.6.1** approved algorithms for key generation and signatures | met — P-256, Ed25519, RSA |
| **V11.1.x** documented key policy and inventory | partial — key lifecycle is documented in ADR-005 and the keys package; there is no single cryptographic inventory document |
| **V11.7.x** in-use memory encryption | not met, and out of scope for a server process |

### V11.2.3: we were generating the weaker key

> "Verify that all cryptographic primitives utilize a minimum of 128-bits of
> security based on the algorithm, key size, and configuration. For example, a
> 256-bit ECC key provides roughly 128 bits of security where RSA requires a
> 3072-bit key to achieve the same."

`keys.Generate` produced **2048-bit** RSA for RS256 and PS256 — roughly 112 bits.
That is the NIST floor for "acceptable until 2030", not the 128-bit floor ASVS
asks for.

P-256 is the default algorithm here and already clears it, which is why this was
easy to miss: almost every deployment signs with ES256. RS256 exists for clients
whose libraries do only RSA — and those clients were being handed the weaker key,
which is exactly backwards.

Now 3072.

**Raising this is free; raising the other RSA floor is not.** They are two
different numbers pulled in opposite directions by two standards:

- **What we generate** is entirely our choice. Clients fetch the modulus from our
  JWKS and verify with whatever we publish. RSA verification is size-agnostic in
  every mainstream library, and the extra cost lands on a path that is not hot.
- **What we accept** from a client stays at 2048 (`clientauth.MinRSABits`),
  because FAPI 2.0 §5.4.1 sets that floor and most clients hold 2048-bit keys.
  Raising it would refuse working integrations to gain sixteen bits of security
  in somebody else's key — and the client is the party bearing that risk.

Strict about our own key, conventional about theirs. The asymmetry is the point.

### V11.4.1: three MD5 sites, and why each stays

MD5 appears in three places, each annotated at the call site:

- **`radius/packet.go`** — RFC 2865 §5.2 specifies MD5 for the User-Password
  keystream and RFC 3579 §3.2 specifies HMAC-MD5 for Message-Authenticator.
  Neither is optional: an access point that expects RFC 2865 will not interoperate
  with anything else. HMAC-MD5 is also not affected by the collision attacks that
  motivate avoiding MD5 — which is precisely why Blast-RADIUS's mitigation *is*
  the HMAC-MD5 attribute.
- **`radius/eapserver.go`** — RFC 2548 MS-MPPE key derivation, same argument.
- **`passwords/foreign.go`** — verifying somebody **else's** stored hash during a
  migration. We never produce these; we read them once, check the password, and
  write an Argon2id hash in their place. Refusing to verify them would mean
  refusing to migrate the deployments this feature exists for.

The first two are the case ASVS's "for any cryptographic purpose" has to bend
around when a protocol predates the guidance. The third is not our hash at all.

### RS256 and PKCS#1 v1.5

V11.3.1 names "weak padding schemes (e.g., PKCS#1 v1.5)". RS256 is
RSASSA-PKCS1-v1_5, and a strict reading catches it.

The requirement's concern is RSAES-PKCS1-v1_5 — the *encryption* padding that
Bleichenbacher's attack breaks. We do not use it: SAML key transport is RSA-OAEP.
RSASSA-PKCS1-v1_5 for signatures remains approved in NIST FIPS 186-5 and is the
`RS256` every OIDC client library implements.

It is still the weakest thing we offer, and it is already recorded as a FAPI
deviation: FAPI 2.0 §5.4.1's list is `PS256, ES256, EdDSA`, and RS256 is not on
it. The decision to keep or drop it is the same decision in both standards, and
it is not mine to make alone — it would refuse every client that implements only
RS256.

## V6 Authentication: forty-seven requirements (21 August 2026)

The largest chapter, and the one this product is most about. No new defects —
which is the expected result for the area that has had the most attention, and is
worth recording as carefully as a finding.

### Met above the bar

| Requirement | Ours |
|---|---|
| **V6.2.1** ≥8 characters, 15 recommended | **15 by default** — NIST SP 800-63B-4 §3.1.1.2's SHALL for single-factor, with a comment recording that the previous value of 8 was an *accurate citation of revision 3*, "the more dangerous kind of stale" |
| **V6.2.9** ≥64 characters permitted | 1024 — and `MaxLength` exists to bound the hasher, not the password: "Argon2 over a megabyte of input is a denial of service with a text box in front of it" |
| **V6.2.8** verified exactly as received | met — `argon2.IDKey([]byte(password), ...)` takes it verbatim; the only `ToLower` is inside the guessability *estimator* and never reaches the hash |
| **V6.2.5** no composition rules | met |
| **V6.2.12** checked against breached passwords | met — `internal/passwords/breached.go` |
| **V6.3.2** no default accounts | met — no migration seeds a user |
| **V6.4.2** no password hints or secret questions | met — nothing of the kind exists |
| **V6.5.1** OTPs usable only once | met — the code hash is nulled on success, under `FOR UPDATE` so two concurrent attempts cannot both spend it. TOTP carries `lastUsed`, the highest counter already accepted, which is the replay check TOTP implementations most often skip |
| **V6.5.3** CSPRNG for codes | met — `rand.Int` rather than modulo over a byte, with the reason written down: "a six-digit code has only a million of them, so the distribution IS the entropy" |
| **V6.5.8** TOTP time from a trusted source | met — the counter is computed server-side and never read from the request |
| **V6.6.3** OOB codes rate limited | met — a per-credential `attempts` counter, and one live code per user by construction |

### V6.8.1, and the reason it is the strongest item here

> "Verify that, if the application supports multiple identity providers (IdPs),
> the user's identity cannot be spoofed via another supported identity provider
> (e.g. by using the same user identifier)."

`internal/federation/decide.go` sets out the attack in five steps and then says:
**"This package has no email-matching path at any setting."** Identities are keyed
`(provider_id, subject)` — a database `UNIQUE` constraint, not a convention — and
attaching an external account to a local one requires authenticating locally
first, which proves control of both sides rather than asserting it from an email
address.


### Partial, and honestly so

- **V6.6.2** — codes bound to the *original authentication request*. Ours are
  bound to the **user**: one live code per account, and requesting another
  replaces the pending one, so guesses cannot accumulate. A code issued during
  one login attempt could be spent in a later attempt by the same user. The
  practical gap is narrow, because spending it still requires the first factor,
  and binding to a session does not stop the relay attack people actually run
  (persuading someone to read a code aloud). Recorded rather than changed.
- **V6.1.x, V6.3.4** — documentation of every authentication pathway and its
  strength. The pathways are documented individually across these reviews; there
  is no single document listing all of them side by side.
- **V6.4.4** — identity proofing at enrolment level when a factor is lost. We
  have recovery codes and delay-and-notify recovery; we do not do identity
  proofing, which is an IAL question rather than an AAL one.
- **V6.3.5, V6.3.7** — notification of suspicious attempts and of credential
  changes. Passkey bind and removal now notify (NIST §4.1.2 and §4.5). Password
  changes and unusual-location sign-ins do not. This is the same missing piece as
  item **9l**: one notification address per account, so the channel is thin.

## ASVS status after this pass

| Chapter | Requirements | State |
|---|---|---|
| V6 Authentication | 47 | swept |
| V7 Session Management | 19 | swept — 1 defect fixed |
| V8 Authorization | 13 | swept — 18 tables corrected |
| V9 Self-contained Tokens | 7 | swept — 1 defect fixed |
| V10 OAuth and OIDC | 36 | swept earlier, 41 of 43 items evidenced |
| V11 Cryptography | 24 | swept — 1 defect fixed |

**146 of 345 requirements** now have a requirement-by-requirement sweep, covering
every chapter that governs an identity provider's core function. The remaining
199 are in chapters about frontend rendering, file handling, WebRTC,
configuration and general secure coding — relevant to the product, not specific
to it, and not where this engine's risk concentrates.

> **That last sentence was wrong about V3, and V3 has now been swept — see
> below.** "Frontend rendering" is where the sign-in page lives, and V3.4 is the
> chapter that says what the browser is told to do with it. The sweep found five
> response headers absent entirely, two of them Level 1.

## CWE coverage, via a tool rather than a recital (21 August 2026)

Point 4 names the CWE Top 25. I could not retrieve it: both
`cwe.mitre.org/top25/archive/2024/` and the 2025 page render their tables in
JavaScript, and the served HTML contains **no CWE identifiers at all** — a scrape
returns zero. The CWE REST API resolves an ID to a name but does not publish the
ranked list.

Listing twenty-five weaknesses from memory and asserting each is handled would be
exactly the reliance this task forbids, and it would produce no evidence. So the
CWE question was answered the other way round: run a tool that maps findings to
CWE identifiers **against the actual code**, and triage what it says.

`gosec` scanned **252 files, 74,737 lines**, and reported 98 findings.

### The two that needed real inspection

**`G407` / CWE-1204, hardcoded IV — `saml/encrypt.go`.** A constant nonce under
AES-GCM destroys the cipher, so this was checked first and in full. It is a false
positive, and an instructive one: the code calls
`cipher.NewGCMWithRandomNonce(block)` and then `gcm.Seal(nil, nil, ...)`. That
API **requires** the nil, because it generates a fresh nonce per call and prepends
it. The rule predates the constructor.

The choice was already deliberate — the surrounding comment explains that the
prefix-IV/suffix-tag layout is exactly what XML Encryption expects, and that
letting the library own the nonce is what makes it work under FIPS 140-only mode,
"where GCM with a caller-supplied IV is refused outright".

**`G118` / CWE-400, request context not used — `httpapi/outpost.go`.** A goroutine
recording an outpost's `last_seen_at` uses `context.Background()` with a
five-second timeout rather than the request context. That is the point rather
than an oversight: the write must **outlive** the request, and `r.Context()` would
cancel it the instant the response is written — so the recording would land only
when the database happened to beat the handler's return. Intermittent, and
diagnosed later as "the outpost stopped reporting".

Both are now annotated with the reason. **Annotated rather than left in the
report**, because a finding everyone has learned to ignore is a finding that hides
the next real one — and a future edit that genuinely introduces a constant nonce
would arrive into a report already containing a G407 nobody reads.

### The remaining 96, by class

| Rule | CWE | Count | Assessment |
|---|---|---|---|
| `G101` | 798 | 37 | Name-pattern false positives. The rule matches identifiers containing "token", "secret", "credential" — ours hold protocol constants: `at+jwt`, `urn:ietf:params:oauth:token-type:access_token`, SAML URNs, provider endpoint URLs, `/oauth2/token` |
| `G304` | 22 | 29 | File reads with a non-constant path; every one is an operator-supplied CLI flag (certificate bundles, the GeoIP database) |
| `G703` | 22 | 8 | The same class under taint analysis. An operator who can set `--ldap-ca` can already read the file |
| `G710` | — | 13 | Style-level |
| `G114`, `G203`, `G204`, `G117`, `G306`, `G706` | various | 9 | Low-severity, reviewed, none attacker-reachable |

The G101 and G304/G703 groups are the tool telling us what it cannot know:
whether a string is a credential, and whether a path is attacker-controlled. In a
server whose entire vocabulary is token type URNs, the first is guaranteed noise.

### Why this is better evidence than a Top 25 checklist

A checklist answers "have you thought about SQL injection". A tool run answers
"here are the 98 places in your code that pattern-match a weakness class, and
here is what each one turned out to be". The second is falsifiable, repeatable,
and produced two annotations that will save the next reader an hour each.

What it does not do is cover the classes gosec has no rule for — business-logic
flaws, authorization gaps, the protocol-level defects that made up almost
everything found this session. Those came from reading specifications against
source, which no scanner does.


## V3 Web Frontend Security: thirty-one requirements (21 August 2026)

This chapter was outside the earlier sweeps, on the reasoning quoted above. That
reasoning was a judgement about a chapter *title*, made without opening the
chapter. An identity provider's sign-in page is the most attacked page it serves,
and V3.4 governs exactly that page.

Requirements taken from the ASVS 5.0.0 JSON export rather than recalled: 345
across 17 chapters, which matches the count already in this document, so it is
the right revision.

### V3.3 Cookie Setup — all five met, nothing to do

Worth recording as met rather than skipped, because it is the part most
applications get wrong and this one did not. Every cookie the engine sets carries
the `__Host-` prefix (`__Host-signari_session`, `__Host-signari_csrf`,
`__Host-signari_pending`, `__Host-signari_ceremony`), which the *browser* enforces
as `Secure` + `Path=/` + no `Domain`, alongside explicit `Secure`, `HttpOnly` and
`SameSite=Lax`. V3.3.1 through V3.3.5 hold, and the `__Host-` choice satisfies
V3.3.1 and V3.3.3 with one mechanism instead of two conventions.

### V3.4 Browser Security Mechanism Headers — the finding

Five headers were absent from the engine entirely. Not weak, not misconfigured —
zero occurrences across `internal/`:

| Requirement | Level | State before | Now |
|---|---|---|---|
| V3.4.4 `X-Content-Type-Options: nosniff` | **L1** | absent | set on every response |
| V3.4.1 `Strict-Transport-Security` | **L1** | absent | `max-age=31536000; includeSubDomains`, https issuers only |
| V3.4.5 `Referrer-Policy` | L2 | absent | `no-referrer` |
| V3.4.3 `base-uri 'none'` in CSP | L2 | absent | appended to all ten policies |
| V3.4.8 `Cross-Origin-Opener-Policy` | L3 | absent | **deliberately still absent — see below** |

**V3.4.4 is the one that mattered.** This server answers JSON on nearly every
endpoint and several of those responses echo caller-supplied values back inside
an `error_description`. Without `nosniff`, a browser may decide a JSON body is
HTML and render it — turning an echoed request parameter into script execution on
the issuer's own origin, which is the origin holding the session cookie. It is a
Level 1 requirement, the baseline, and it was missing from every response the
engine has ever sent.

**V3.4.3 and the directive that has no fallback.** Our policies opened with
`default-src 'none'`, which covers `object-src` — that directive falls back to
`default-src`. **`base-uri` does not.** It is deliberately outside the
`default-src` chain, which is precisely why V3.4.3 names both explicitly rather
than one. So every page this server rendered left `<base>` unrestricted,
including the sign-in page, where `script-src` is relaxed to `'self'` and widened
further to a provider's origins when a CAPTCHA is configured.

With `script-src 'self'` an injected `<base>` cannot pull script from another
origin, so this is hardening rather than a live hole — and it is one directive,
named by the standard, providing exactly the protection that disappears the next
time somebody widens a policy.

**How it was fixed matters more than that it was.** There were ten places
building a CSP by hand. Editing ten string literals fixes ten pages and does
nothing about the eleventh, written next month by someone starting from a copy of
whichever one they found first. All ten now go through `setCSP`, which appends
the invariants. There is one place left that can forget them, and it is the one
place a test points at.

### V3.4.8 Cross-Origin-Opener-Policy: not set, and why

`COOP: same-origin` severs `window.opener` when a cross-origin document opens
ours in a popup. Popup-mode OIDC is a real and common relying-party pattern: the
RP opens `/oauth2/authorize` in a popup and its own callback page messages the
opener when the flow completes. Setting COOP on the authorization, login or
consent pages breaks that chain — the popup lands back on the RP's origin with
`window.opener` already null.

`same-origin-allow-popups` does not help; it governs popups *we* open, not the
opener relationship of a popup we are inside.

So this L3 requirement is not met, deliberately, with the reason recorded. The
alternative — meeting an L3 header by breaking a documented integration pattern
for relying parties — would be scoring a checklist rather than securing anything.

### The rest of V3

| Section | Verdict |
|---|---|
| V3.1.1 documentation of expected browser features | L3, partially — the headers are documented here and in the middleware, the "behave when unavailable" half is not |
| V3.2.1 / V3.2.2 content interpretation | met — `nosniff` now, and all rendering goes through `html/template`, which escapes by context |
| V3.2.3 DOM clobbering | not applicable — the sign-in form needs no JavaScript at all, proven by a standing test |
| V3.4.2 CORS allowlist | met — a fixed allowlist, checked earlier under V10 |
| V3.4.6 `frame-ancestors` | met — every page sets it to `'none'`; note ASVS considers `X-Frame-Options` obsolete, and we send both |
| V3.4.7 CSP report location | L3, not set |
| V3.5.1–V3.5.3 origin separation / CSRF | met — per-session CSRF tokens on every state-changing form, `POST` for every sensitive operation |
| V3.5.5 postMessage | not applicable — zero uses |
| V3.5.6 JSONP | not applicable — zero uses |
| V3.6.1 subresource integrity | not applicable by default — no external assets are loaded; the CAPTCHA case is the sole exception and already carries a written justification at the CSP that permits it |
| V3.7.2 redirect allowlist | met — `redirect_uri` is an exact-match allowlist per client |
| V3.7.4 HSTS preload | not done; a deployment decision for whoever owns the domain, not the engine |

### Mutation results

```
CAUGHT   middleware not wired into Routes()      (no nosniff on any response)
CAUGHT   base-uri dropped from the invariants    (policy sent without it)
CAUGHT   HSTS gate inverted                      (absent on an https issuer)
```

The first is the one worth having. A middleware that is correct and a middleware
that is *reachable* are different claims, and only a test that goes through the
router checks the second — every existing sign-in page test in this package calls
the handler directly and would have passed with the middleware unwired.

### Chapter coverage after this pass

**177 of 345.** V3 joins V6, V7, V8, V9, V10 and V11. The chapters still unswept
are V1 Encoding, V2 Validation, V4 API, V5 File, V12 Secure Communication, V13
Configuration, V14 Data Protection, V15 Secure Coding, V16 Logging and V17
WebRTC — and after this pass, the claim that they are unlikely to matter should
be treated as untested rather than as a finding. V3 was in that list yesterday.
