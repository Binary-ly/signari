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
