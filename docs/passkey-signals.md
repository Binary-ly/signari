# Keeping authenticators in step — WebAuthn Level 3 signals

```
GET /account/passkeys/signal        what the browser needs
GET /static/passkey-signal.js       the page-side half
```

## The bug

An administrator deletes somebody's passkey. The record is gone here; **the
credential is still on the authenticator**, and the platform goes on offering it
at every sign-in. The user picks it, it fails, and nothing in the interface
explains why. On a password manager syncing across four devices, the stale entry
follows them everywhere.

Every identity provider has this bug, because until Level 3 there was no way to
tell an authenticator that a credential is no longer known.

## What Level 3 added

| | |
|---|---|
| `signalUnknownCredential()` | one credential is not recognised |
| `signalAllAcceptedCredentials()` | here is the complete list; forget the rest |
| `signalCurrentUserDetails()` | the name shown for this account changed |

[WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/), Candidate Recommendation,
**26 May 2026**.

## Who else implements it


## Conformance review against WebAuthn L3, August 2026

Reviewed against the spec text. The dictionaries match field for field
(`AllAcceptedCredentialsOptions`, `CurrentUserDetailsOptions`), ids are
`Base64URLString` unpadded, and the script ignores results — §5.1.10 is explicit
that "signal methods do not indicate whether the operation succeeded", so a page
that branched on the outcome would be reading noise.

Requiring a session before returning the credential-id list turns out to be what
**§14.6.3 itself recommends**: *"Perform a separate authentication step ... before
initiating the WebAuthn authentication ceremony and exposing the user's
credential IDs."*

**One gap found: `signalUnknownCredential` was not implemented.**

§5.1.10.3 says to prefer `signalAllAcceptedCredentials` *"when the user is
authenticated"* — and that is what we had. But a failed sign-in is precisely when
they are **not**, and a user whose **only** passkey was deleted can never reach
the authenticated path: the single credential they hold is the one that cannot
sign them in. They are stuck being offered it forever.

So a refused assertion now names the credential it refused:

```json
{ "error": "invalid_grant",
  "error_description": "the passkey was not accepted",
  "signal_unknown_credential": { "rpId": "example.com", "credentialId": "AQIDBA" } }
```

The id is captured in the credential-resolution closure, because the library
returns a nil credential on failure and that closure is the only place it exists.

**It discloses nothing.** The caller just presented that id, so returning it
tells them something they already had — §14.6.3's concern is about exposing ids
to somebody who did *not* have them.

And it is **omitted when we cannot name the credential**. A rejection for some
other reason — a bad signature from a credential we still hold — must not tell
the browser to forget a perfectly valid one.

## The payload

```json
{ "rpId": "example.com",
  "userId": "q9lfMLcJpoU1A6-PApqrD…",
  "allAcceptedCredentialIds": ["MS-RKF4Ejgm7Su_vI2J5lA", "MWS1IudGaDevZKzu_pdm6Q"],
  "name": "alice@example.com",
  "displayName": "Alice" }
```

Field names are the specification's, so the page passes the object straight
through. **Transcription is where a field name gets mistyped**, and a mistyped
parameter does not error — the call silently does nothing, on every browser, for
every user. A test asserts the exact five names for that reason.

Verified against a running engine:

```
three registered:   3 credential(s): [MS-RKF4…, 96Qv5y…, MWS1Iu…]
phone deleted:      2 credential(s): [MS-RKF4…, MWS1Iu…]
all deleted:        0 credential(s): []
```

**An empty list is a real instruction** — "forget every credential you hold for
me" — so it serialises as `[]`, never `null`. The user whose last passkey was
deleted is exactly the case that has to work.

## Why it needs a session

The list of credential ids for an account is a fingerprint of it: how many
authenticators, and which. Unauthenticated callers get `401` and nothing else —
otherwise a bug fix becomes a user-enumeration endpoint.

Where passkeys are not configured at all (no `rp_id`), the answer is `501`, not an
error: that is a deployment choice, and a 500 would put a console error on every
sign-in of a deployment that simply does not use passkeys.

## Why the script is a file

Served at a stable URL rather than inlined, so the Content-Security-Policy does
not need `'unsafe-inline'`. A version that only worked with inline script would
push us to weaken the CSP to fix a cosmetic problem.

Every call is individually guarded. The methods reached browsers at different
times, so a browser without one is ordinary rather than an error — and a page
that throws on an older browser has made a working sign-in worse in order to tidy
a stale entry.


## Re-review against WebAuthn Level 3, August 2026

Version checked first: **W3C Candidate Recommendation Snapshot, 26 May 2026** —
current, and the version implemented against.

### The defect: a valid passkey could be deleted by a transient failure

`signalUnknownCredential` tells an authenticator to **delete** a credential. It
exists for exactly one case (§5.1.10.2): a passkey the server has removed, which
the authenticator keeps offering — and which the user cannot clear any other way,
because `signalAllAcceptedCredentials` needs a session and the credential that
would earn them one is the broken one.

The cure is destructive, and at the top of an assertion handler the case it cures
is indistinguishable from every other failure.

The credential id was captured unconditionally, at the first line of the
resolution closure, **before the user was resolved and before any signature was
verified**:

```go
handler := func(rawID, userHandle []byte) (webauthn.User, error) {
    presentedID = append([]byte(nil), rawID...)
    ...
```

So *any* failed assertion came back carrying `signal_unknown_credential` — a
user-verification timeout, a sign-count regression, a corrupted signature, a
transient authenticator fault. The browser is then told to forget a credential
the server still holds and would happily accept.

For a user whose only passkey it was, that is a **self-inflicted lockout produced
by the feature meant to prevent one**.

The refusal helper's own comment already stated the correct rule — *"A rejection
for some other reason -- a bad signature from a credential we DO still hold --
must not tell the browser to forget a credential that is perfectly valid"* — but
its guard was `rpID != "" && len(presentedID) > 0`, which tests whether we can
*name* the credential, not whether it is *unknown*. The two are not the same, and
the comment made the gap read as a decision.

Fixed with a `held` flag set while the user's credential list is in hand, which
is the only point where the question can actually be answered. The library does
not distinguish these failures in its error, so inferring it afterwards was never
going to work.

| Mutation | Test that caught it |
|---|---|
| Remove the `held` guard | `TestAKnownCredentialIsNeverSignalledAsUnknown` |

The first attempt at that mutation deleted the guard outright and produced a
*build* failure — the compiler noticing an unused variable, not the test doing
its job. Redone as `if false && held` so it compiles, the test fails with the
message naming the consequence. Worth recording: a mutation that fails to compile
proves nothing about the test.

### What came back clean

| Requirement | Where | Result |
|---|---|---|
| `AllAcceptedCredentialsOptions` / `CurrentUserDetailsOptions` field names and required-ness | §5.1.10.3–4 | exact, pinned by test |
| `userId` is a `Base64URLString` of the user handle | dictionaries | `base64.RawURLEncoding` of `core.users.user_handle`, the same value the ceremony uses |
| Unpadded encoding | `Base64URLString` | `RawURLEncoding` |
| Credential ids not disclosed to an unauthenticated caller | §14.6.3 | `/account/passkeys/signal` answers 401 without a session |
| `signalUnknownCredential` discloses nothing new | §14.6.3 | echoes back only the id the caller just presented |
| Empty credential list serialises as `[]`, not `null` | §5.1.10.3 | pinned by test — "forget everything" is a real instruction |

The `userId` check is the one worth dwelling on: a wrong value there does not
error, it silently does nothing, on every browser, for every user. Reading it
from the same column the ceremony uses is what makes it right, and reading it
from a second place is how it would drift.

---

## Third pass, August 2026: a signal we were discarding

Re-read against the **W3C Candidate Recommendation Snapshot, 26 May 2026** —
still the current version, checked rather than assumed.

### The condition is a disjunction, and ours was a conjunction

§7.2 step 21, verbatim:

> If `authData.signCount` is nonzero **or** `credentialRecord.signCount` is
> nonzero, then run the following sub-step:
> - **greater than** `credentialRecord.signCount`: The signature counter is valid.
> - **less than or equal to** `credentialRecord.signCount`: This is a signal, but
>   not proof, that the authenticator may be cloned.

Ours read:

```go
cloned := stored != 0 && presented != 0 && presented <= stored
```

An **and** where the specification has an **or**. The difference is exactly one
case: a credential whose stored counter is non-zero that now presents **zero**.

| stored | presented | Spec | Ours (before) |
|---|---|---|---|
| 0 | 0 | skipped | skipped |
| 0 | N | valid | valid |
| N | >N | valid | valid |
| N | ≤N, non-zero | **signal** | signal |
| **N** | **0** | **signal** | **ignored** |

And that last row is the one case that *cannot* be explained by "this
authenticator does not implement counters" — because it evidently did, right up
until this assertion.

### The rationale for the deviation described something that does not happen

The deviation was deliberate. The test case carried this comment:

> A stored non-zero counter followed by zero is an authenticator that stopped
> counting, not a clone — and rejecting it would lock out a user whose device was
> replaced or firmware updated.

**Nothing in this system rejects.** `internal/httpapi/passkey.go` treats
`ErrCredentialCloned` as a warning: it logs, writes an
`mfa.passkey_counter_regression` audit event, and then calls `completeSignIn`.
The sign-in succeeds. There is no lockout to weigh against the signal, so the
trade-off the comment describes was never being made.

That makes it a **false rationale** rather than a considered choice — the same
defect class this repository has now found three times in its own text: a comment
asserting a consequence, a control, or a check that is not there. The pattern is
consistent enough to be worth naming: *the justification outlives the code it was
written about.*

The fix is one operator:

```go
cloned := (stored != 0 || presented != 0) && presented <= stored
```

Passkeys that always report zero — most of the ones in the world, because a
credential synced across devices cannot keep a coherent counter — are unaffected:
their stored value stays zero forever, so the disjunction stays false and the
sub-step is skipped exactly as before.

### Still evidence, not proof

Nothing about the handling changed, and that remains the important part. A
counter regression can be a clone, a malfunctioning authenticator, or a race
between two concurrent assertions. It is recorded at WARN and audited so an
operator can act on a *pattern*; it does not destroy a credential or refuse a
sign-in, because a false positive there locks a legitimate user out of their own
account.

## Which authenticators an organisation accepts

An organisation may require that passkeys come from approved authenticator
models — hardware keys of a particular make, for instance. Two settings, both
per organisation:

| | |
|---|---|
| `attestation_conveyance` | What to ask the browser for: `none` (default), `indirect`, `direct` or `enterprise` |
| `allowed_aaguids` | Approved authenticator models. Empty accepts any |

**Attestation is off by default, and that is a decision rather than an
oversight.** Requesting it sends the authenticator's attestation statement, which
identifies the device model and, for some vendors, a manufacturing batch. The
WebAuthn specification and every browser vendor made `none` the default
deliberately — it is the privacy-preserving choice, and some browsers show the
user an extra prompt when a site asks for more. A deployment without an
approved-device requirement should not be collecting device identifiers from its
users by accident.

**An AAGUID from a `none` registration is self-asserted.** The authenticator data
carries an AAGUID either way, and with no attestation nothing vouches for it — a
software authenticator can put a hardware vendor's identifier in the field.
Filtering on it would be filtering a value chosen by the party being filtered.

So the allow-list **refuses rather than compares** when attestation was not
conveyed, the database refuses a policy that names an allow-list alongside
conveyance `none`, and each credential records whether its AAGUID was vouched
for at registration — a later policy change cannot retroactively make an old
credential's AAGUID trustworthy.

The all-zero AAGUID never matches anything. It means "I decline to identify
myself", which every privacy-preserving authenticator sends, and treating it as a
value would let all of them match a single allow-list entry of zeroes.

### What this proves, and what it does not

With conveyance raised, the attestation statement's format and signature are
verified. **The attestation certificate is not validated against a FIDO Metadata
Service root**, because this deployment holds no MDS attestation roots —
`internal/fidomds` maps AAGUIDs to model names and carries no certificates.

Stated plainly: the allow-list stops a casual software authenticator, which
cannot produce a well-formed packed attestation for a hardware vendor's AAGUID.
It does not stop somebody who obtains a genuine attestation key. That is a real
control with a stated ceiling, and the ceiling is written here so nobody builds a
compliance claim on top of more than it delivers.
