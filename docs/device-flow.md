# Device authorization grant

RFC 8628, for inputs that cannot host a browser: a television, a CLI, a headless
box. The device shows a short code, the person types it somewhere with a browser,
and the device polls until they approve.

```
POST /oauth2/device_authorization    the device asks
GET|POST /device                     the person approves
POST /oauth2/token                   the device polls
```

```json
{
  "device_code": "zf1iW_ZV_sSkUpybCsTcYWm9JVShqPKYjRtYpPjfecU",
  "user_code": "VEUY-LEJF",
  "verification_uri": "https://auth.example.com/device",
  "verification_uri_complete": "https://auth.example.com/device?user_code=VEUY-LEJF",
  "expires_in": 600,
  "interval": 5
}
```

Both URI forms are returned. The plain one is what a person types; the
`_complete` variant carries the code, so a QR code on the screen means no typing
at all — the difference between a usable television login and a hated one.

## The attack this is shaped around

**Device code phishing.** An attacker starts the flow on their own device, gets a
user code, and sends it to a victim with a plausible story. The victim types it
into the *real* identity provider, sees a *real* consent screen, approves — and
the attacker's device receives the tokens. Nothing in the protocol is violated.
The victim authorised the wrong device.

Nothing can prevent that outright, so the design narrows it:

- **Ten-minute expiry.** Some implementations allow hours. Nobody legitimately
  takes an hour to type eight letters, and every extra minute is phishing window.
- **The confirmation screen names the client** and says plainly that a *device* is
  being authorised, with the scopes it will get. That screen is the only place a
  phished person is told what they are actually approving.
- **It says so explicitly**: *"Nobody legitimate will ask you to enter a code they
  sent you."*
- **Refusing is a first-class button**, and refusing says that somebody may have
  tried to phish them.

## The user code

Eight characters from a 21-letter alphabet — A–Z without **B, I, O, S, Z**, and
no digits at all. Every exclusion is a misreading people actually make copying a
code off a screen across a room: I/1/l, O/0, S/5, Z/2, B/8. That is ~35 bits,
comfortably past the 20 RFC 8628 §5.1 asks for against a rate-limited endpoint.

Normalisation forgives case, hyphens, spaces and underscores — and **nothing
else**. A draft mapped "confusable" characters to what the reader supposedly
meant; it rewrote `L`, which *is* in the alphabet, and mapped `Z` to a character
that is not. That silently corrupts a correct code into one that can never match,
producing a failure nobody can reproduce. `TestNormalizeDoesNotRewriteAlphabetCharacters`
now pins the rule.

## Rate limiting, and the counter that was removed

The verification endpoint is rate limited (3/s, burst 10), which is what RFC 8628
§5.1 asks for.

A per-record attempt counter was drafted first — `failed_attempts` on the table,
with the record destroyed after five wrong guesses. It was removed before it
shipped, because **it cannot work**: when somebody types a wrong code there is no
record to charge it to, since we cannot know which one they were aiming at. It
would have been a column nothing increments and a function nothing calls, which
is the exact defect this project keeps finding in itself — see
`security-scanning.md`.

## What is checked, in what order

Order matters here, and getting it wrong was a real bug in the first version.

The client id is verified **inside the polling transaction, before anything is
consumed**. Originally the caller checked it *after* `PollDeviceCode`, which marks
an approved code redeemed — so anyone holding a leaked device code could present
any client id, have the approval burned, and leave the legitimate device stuck on
`expired_token` forever. A denial of service against a completed login.

The full order: client id → expiry → already-redeemed → polling interval →
status.

The polling interval is checked *before* the status, so a device that hammers the
endpoint is slowed whether or not the person has approved yet. Checking it after
would apply the rule only to the boring case.

`slow_down` adds five seconds to the stored interval and persists it, per §3.5 —
so the requirement is real rather than a suggestion the client may ignore.

## Verified end to end

Against the running server:

| | |
|---|---|
| poll before approval | `authorization_pending` |
| poll again immediately | `slow_down` |
| **another client presents the code** | `invalid_grant`, nothing consumed |
| unknown device code | `expired_token` |
| type the code signed in | confirmation naming **Group Test (grouptest)**, scopes `openid`, `profile` |
| approve, then poll | tokens issued |
| **replay the same device code** | `expired_token` — single use |

The ID token was checked rather than assumed: `sub` matches the user who
approved, `amr` is `["pwd"]` — truthfully what they did — and `sid` binds it to
the browser session that granted it.

## Single credential path

Tokens are minted through `mintSet`, the same function every other grant uses, so
a device grant gets the same DPoP binding, resource indicators, group claims and
audit trail. A second minting path would be a second place for those to be
forgotten.

Unknown, expired and already-redeemed device codes all answer `expired_token`.
Telling a caller their code was once real narrows a guess.

Abandoned authorizations are swept by the janitor an hour after expiry — each row
holds two code hashes, and a television login nobody finished should not leave
them behind.
