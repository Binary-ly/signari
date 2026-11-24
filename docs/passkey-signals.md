# Keeping authenticators in step — WebAuthn Level 3 signals

## Introduction

A "passkey" is a sign-in credential kept on a device or in a password manager.
When an administrator deletes somebody's passkey in Signari, the device does not
know. It keeps offering the passkey at every sign-in, and the sign-in fails.

WebAuthn, the browser standard behind passkeys, added "signals" in its Level 3,
so that a site can tell a device which passkeys it still accepts. Signari sends
those signals. This page also records how they were checked against the
specification, which authenticators an organisation can accept, and how a person
can sign in without a password.

Signals need passkeys to be configured for the instance, with an `rp_id`. The
authenticators an organisation accepts are set for each organisation.

## The two addresses

Two addresses serve the signals:

```
GET /account/passkeys/signal        what the browser needs
GET /static/passkey-signal.js       the page-side half
```

## The bug

An administrator deletes somebody's passkey. The record is gone from Signari,
but **the credential is still on the authenticator**, and the platform goes on
offering it at every sign-in. The person picks it, it fails, and nothing in the
interface explains why. On a password manager syncing across four devices, the
stale entry follows them everywhere.

Every identity provider has this bug, because until Level 3 there was no way to
tell an authenticator that a credential is no longer known.

## What Level 3 added

Level 3 added three signals:

| | |
|---|---|
| `signalUnknownCredential()` | one credential is not recognised |
| `signalAllAcceptedCredentials()` | here is the complete list; forget the rest |
| `signalCurrentUserDetails()` | the name shown for this account changed |

They are in [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/), a Candidate
Recommendation dated **26 May 2026**.

## Conformance review against WebAuthn L3, August 2026

This was reviewed against the specification's text. The dictionaries match
field for field (`AllAcceptedCredentialsOptions`, `CurrentUserDetailsOptions`),
and ids are `Base64URLString` unpadded.

The script ignores results. §5.1.10 is explicit that "signal methods do not
indicate whether the operation succeeded". So a page that branched on the
outcome would be reading noise.

Requiring a session before returning the credential-id list turns out to be what
**§14.6.3 itself recommends**: *"Perform a separate authentication step ... before
initiating the WebAuthn authentication ceremony and exposing the user's
credential IDs."*

**One gap found: `signalUnknownCredential` was not implemented.**

§5.1.10.3 says to prefer `signalAllAcceptedCredentials` *"when the user is
authenticated"*, and that is what Signari had. But a failed sign-in is precisely
when the person is **not** authenticated. A person whose **only** passkey was
deleted can never reach the authenticated path. The single credential they hold
is the one that cannot sign them in, so they are stuck being offered it forever.

So a refused "assertion", the passkey's signed answer at sign-in, now names the
credential it refused:

```json
{ "error": "invalid_grant",
  "error_description": "the passkey was not accepted",
  "signal_unknown_credential": { "rpId": "example.com", "credentialId": "AQIDBA" } }
```

The id is captured in the credential-resolution closure. The library returns a
nil credential on failure, and that closure is the only place the id exists.

**It discloses nothing.** The caller presented that id a moment before, so
returning it tells them something they already had. §14.6.3's concern is about
exposing ids to somebody who did *not* have them.

And it is **omitted when Signari cannot name the credential**. A rejection for
some other reason, such as a bad signature from a credential Signari still
holds, must not tell the browser to forget a perfectly valid one.

## The payload

`/account/passkeys/signal` answers with an object like this:

```json
{ "rpId": "example.com",
  "userId": "q9lfMLcJpoU1A6-PApqrD…",
  "allAcceptedCredentialIds": ["MS-RKF4Ejgm7Su_vI2J5lA", "MWS1IudGaDevZKzu_pdm6Q"],
  "name": "alice@example.com",
  "displayName": "Alice" }
```

Field names are the specification's, so the page passes the object straight
through. **Transcription is where a field name gets mistyped**, and a mistyped
parameter does not error. The call silently does nothing, on every browser, for
every person. A test asserts the exact five names for that reason.

This was verified against a running engine:

```
three registered:   3 credential(s): [MS-RKF4…, 96Qv5y…, MWS1Iu…]
phone deleted:      2 credential(s): [MS-RKF4…, MWS1Iu…]
all deleted:        0 credential(s): []
```

**An empty list is a real instruction**: "forget every credential you hold for
me". So it serialises as `[]`, never `null`. The person whose last passkey was
deleted is exactly the case that has to work.

## Why it needs a session

The list of credential ids for an account is a fingerprint of it: how many
authenticators, and which. Unauthenticated callers get `401` and nothing else.
Otherwise a bug fix would become an endpoint that tells anyone which accounts
exist.

Where passkeys are not configured at all (no `rp_id`), the answer is `501`, not
an error. That is a deployment choice. A 500 would put a console error on every
sign-in of a deployment that does not use passkeys.

## Why the script is a file

The script is served at a stable URL, not inlined, so the
Content-Security-Policy does not need `'unsafe-inline'`. A version that only
worked with inline script would push Signari to weaken its Content Security
Policy (CSP) to fix a cosmetic problem.

Every call is individually guarded. The methods reached browsers at different
times, so a browser without one is ordinary, not an error. A page that throws on
an older browser has made a working sign-in worse, in order to tidy a stale
entry.


## Re-review against WebAuthn Level 3, August 2026

The version was checked first: **W3C Candidate Recommendation Snapshot, 26 May
2026**. That is current, and the version implemented against. W3C is the World
Wide Web Consortium, which publishes WebAuthn.

### The defect: a valid passkey could be deleted by a transient failure

`signalUnknownCredential` tells an authenticator to **delete** a credential. It
exists for exactly one case (§5.1.10.2): a passkey Signari has removed, which
the authenticator keeps offering. The person cannot clear it any other way.
`signalAllAcceptedCredentials` needs a session, and the credential that would
earn them one is the broken one.

The cure is destructive. At the top of an assertion handler, the case it cures
is indistinguishable from every other failure.

The credential id was captured unconditionally, at the first line of the
resolution closure, **before the person was resolved and before any signature
was verified**:

```go
handler := func(rawID, userHandle []byte) (webauthn.User, error) {
    presentedID = append([]byte(nil), rawID...)
    ...
```

So *any* failed assertion came back carrying `signal_unknown_credential`. That
included a timeout while the authenticator checked the person, a sign-count
regression, a corrupted signature, and a transient authenticator fault. The
browser was then told to forget a credential Signari still holds, and would
happily accept.

For a person whose only passkey it was, that is a **self-inflicted lockout
produced by the feature meant to prevent one**.

The refusal helper's own comment already stated the correct rule: *"A rejection
for some other reason -- a bad signature from a credential we DO still hold --
must not tell the browser to forget a credential that is perfectly valid"*. But
its guard was `rpID != "" && len(presentedID) > 0`. That tests whether Signari
can *name* the credential, not whether it is *unknown*. The two are not the same,
and the comment made the gap read as a decision.

It was fixed with a `held` flag, set while the person's credential list is in
hand. That is the only point where the question can actually be answered. The
library does not distinguish these failures in its error, so inferring it
afterwards was never going to work.

The fix was checked by a "mutation": breaking the code on purpose, and seeing
which test fails:

| Mutation | Test that caught it |
|---|---|
| Remove the `held` guard | `TestAKnownCredentialIsNeverSignalledAsUnknown` |

The first attempt at that mutation deleted the guard outright, and produced a
*build* failure. That was the compiler noticing an unused variable, not the test
doing its job. Redone as `if false && held` so that it compiles, the test fails
with the message naming the consequence. Worth recording: a mutation that fails
to compile proves nothing about the test.

### What came back clean

These requirements were met as written:

| Requirement | Where | Result |
|---|---|---|
| `AllAcceptedCredentialsOptions` / `CurrentUserDetailsOptions` field names and required-ness | §5.1.10.3–4 | exact, pinned by test |
| `userId` is a `Base64URLString` of the user handle | dictionaries | `base64.RawURLEncoding` of `core.users.user_handle`, the same value the ceremony uses |
| Unpadded encoding | `Base64URLString` | `RawURLEncoding` |
| Credential ids not disclosed to an unauthenticated caller | §14.6.3 | `/account/passkeys/signal` answers 401 without a session |
| `signalUnknownCredential` discloses nothing new | §14.6.3 | echoes back only the id the caller presented |
| Empty credential list serialises as `[]`, not `null` | §5.1.10.3 | pinned by test — "forget everything" is a real instruction |

The `userId` check is the one worth dwelling on. A wrong value there does not
error: it silently does nothing, on every browser, for every person. Reading it
from the same column the ceremony uses is what makes it right. Reading it from a
second place is how it would drift.

---

## Third pass, August 2026: a signal we were discarding

This was re-read against the **W3C Candidate Recommendation Snapshot, 26 May
2026**. That is still the current version, checked rather than assumed.

### The condition is a disjunction, and ours was a conjunction

A "disjunction" is a condition joined by **or**, and a "conjunction" is one
joined by **and**. This is §7.2 step 21, verbatim:

> If `authData.signCount` is nonzero **or** `credentialRecord.signCount` is
> nonzero, then run the following sub-step:
> - **greater than** `credentialRecord.signCount`: The signature counter is valid.
> - **less than or equal to** `credentialRecord.signCount`: This is a signal, but
>   not proof, that the authenticator may be cloned.

Signari's code read:

```go
cloned := stored != 0 && presented != 0 && presented <= stored
```

That is an **and** where the specification has an **or**. The difference is
exactly one case: a credential whose stored counter is non-zero, that now
presents **zero**. This table shows every case:

| stored | presented | Spec | Ours (before) |
|---|---|---|---|
| 0 | 0 | skipped | skipped |
| 0 | N | valid | valid |
| N | >N | valid | valid |
| N | ≤N, non-zero | **signal** | signal |
| **N** | **0** | **signal** | **ignored** |

And that last row is the one case that *cannot* be explained by "this
authenticator does not implement counters". It evidently did, right up until
this assertion.

### The rationale for the deviation described something that does not happen

The deviation was deliberate. The test case carried this comment:

> A stored non-zero counter followed by zero is an authenticator that stopped
> counting, not a clone — and rejecting it would lock out a user whose device was
> replaced or firmware updated.

**Nothing in this system rejects.** `internal/httpapi/passkey.go` treats
`ErrCredentialCloned` as a warning. It logs, writes an
`mfa.passkey_counter_regression` audit event, and then calls `completeSignIn`.
The sign-in succeeds. There is no lockout to weigh against the signal, so the
trade-off the comment describes was never being made.

That makes it a **false rationale**, not a considered choice. It is the same
defect class this repository has now found three times in its own text: a
comment asserting a consequence, a control, or a check that is not there. The
pattern is consistent enough to be worth naming: *the justification outlives the
code it was written about.*

The fix turns the first `&&` into `||`, and brackets the pair:

```go
cloned := (stored != 0 || presented != 0) && presented <= stored
```

Passkeys that always report zero are unaffected. They are most of the ones in
the world, because a credential synced across devices cannot keep a coherent
counter. Their stored value stays zero forever, so the disjunction stays false,
and the sub-step is skipped exactly as before.

### Still evidence, not proof

Nothing about the handling changed, and that remains the important part. A
counter regression can be a clone, a malfunctioning authenticator, or a race
between two concurrent assertions.

It is recorded at WARN and audited, so an administrator can act on a *pattern*.
It does not destroy a credential or refuse a sign-in, because a false positive
there locks a legitimate person out of their own account.

## Which authenticators an organisation accepts

An organisation can require that passkeys come from approved authenticator
models, such as hardware keys of a particular make. There are two settings, both
per organisation:

| | |
|---|---|
| `attestation_conveyance` | What to ask the browser for: `none` (default), `indirect`, `direct` or `enterprise` |
| `allowed_aaguids` | Approved authenticator models. Empty accepts any |

**Attestation is off by default, and that is a decision, not an oversight.**
"Attestation" is an authenticator's signed statement of what it is. Requesting
it sends that statement, which identifies the device model and, for some
vendors, a manufacturing batch.

The WebAuthn specification and every browser vendor made `none` the default
deliberately. It is the privacy-preserving choice, and some browsers show the
person an extra prompt when a site asks for more. A deployment without an
approved-device requirement should not be collecting device identifiers from its
people by accident.

**An AAGUID from a `none` registration is self-asserted.** An AAGUID
(Authenticator Attestation Globally Unique Identifier) names an authenticator's
model. The authenticator data carries an AAGUID either way, and with no
attestation nothing vouches for it. A software authenticator can put a hardware
vendor's identifier in the field. Filtering on it would be filtering a value
chosen by the party being filtered.

So the allow-list **refuses rather than compares** when attestation was not
conveyed. The database refuses a policy that names an allow-list alongside
conveyance `none`. Each credential also records whether its AAGUID was vouched
for at registration. A later policy change cannot retroactively make an old
credential's AAGUID trustworthy.

The all-zero AAGUID never matches anything. It means "I decline to identify
myself", which every privacy-preserving authenticator sends. Treating it as a
value would let all of them match a single allow-list entry of zeroes.

### What this proves, and what it does not

With conveyance raised, the attestation statement's format and signature are
verified. **The attestation certificate is not validated against a FIDO Metadata
Service root**, because this deployment holds no MDS attestation roots. FIDO is
the Fast IDentity Online alliance, whose Metadata Service (MDS) lists
authenticator models. `internal/fidomds` maps AAGUIDs to model names, and carries
no certificates.

Stated plainly: the allow-list stops a casual software authenticator, which
cannot produce a well-formed packed attestation for a hardware vendor's AAGUID.
It does not stop somebody who obtains a genuine attestation key. That is a real
control with a stated ceiling. The ceiling is written here so that nobody builds
a compliance claim on top of more than it delivers.

## Signing in without a password

Somebody with **two** passkeys can remove their password at `/account/security`.
It needs a recent sign-in, and is never allowed in an impersonation. It is
audited as `user.password_removed`, and the person is told on every channel.

One passkey is not enough, because losing that device would end the account. A
passkey cannot be copied off its authenticator, and with no password left,
nothing else would let them in. The page says so, instead of hiding the button
without a reason.

Two are still not enough where the organisation's sign-in flow takes no passkey
alone, such as a flow that asks for the password on every sign-in. Removing the
password there would leave the person a way in that the flow refuses.

The directory's `delete userPassword` passes the same rule. It used to delete
the password of somebody with no passkey at all, leaving an account nobody could
sign in to. A person without a password sets one through account recovery.
Signing up with a passkey in place of a password is not built yet.

## A passkey that stops being backed up

A synced passkey reports, on each sign-in, whether it is backed up (the BS flag
of WebAuthn §6.1.3). It can go from backed up to not, when a backup service is
turned off or fails. Losing that one device would then lose the passkey.

The specification names the site the "relying party", and says it "SHOULD guide
the user through a process to validate their other authentication factors". So
besides `mfa.passkey_backup_lost`, the person is told, by mail and by text
message where a number is verified. The message names the passkey, and links to
their security page. There they can see what else signs them in, and add
another.

They are told once per transition. The new state is stored with the sign-in, so
the next one from it says nothing, until the passkey is backed up again and
loses it again. Until October 2026, only the audit record was written.
