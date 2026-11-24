# Device authorization grant

## Introduction

Some devices cannot show a browser: a television, a command-line tool, a box with
no screen at all. The "device authorization grant", defined in RFC 8628, lets
them sign a person in anyway. People often call it the "device flow" (see the
[glossary](glossary.md#device-flow)).

The device shows a short code. The person types it somewhere with a browser, such
as their phone, and the device polls Signari until they approve. This page
explains how Signari keeps that flow safe, because it is open to abuse.

An application must be registered for this grant before it can use it. You do
that with `signari client set-grants`, as shown in [The client must be registered
for the grant](#the-client-must-be-registered-for-the-grant).

## The three steps

The flow uses three addresses, one for each step:

```
POST /oauth2/device_authorization    the device asks
GET|POST /device                     the person approves
POST /oauth2/token                   the device polls
```

When the device asks, Signari answers with the codes and where to type them:

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

In this example, `user_code` is the code the person types, and the standard calls
it the "user code". The device keeps `device_code` to itself and polls with it.
`expires_in` is how many seconds the codes last, and `interval` is how many
seconds to wait between polls.

Both URI forms are returned. The plain one is what a person types. The
`_complete` variant carries the code, so a QR code on the screen means no typing
at all. That is the difference between a usable television sign-in and a hated
one.

## The attack this is shaped around

**Device code phishing.** An attacker starts the flow on their own device and gets
a code. They send it to a victim with a plausible story. The victim types it into
the *real* identity provider, sees a *real* consent screen, and approves. Then the
attacker's device receives the tokens. Nothing in the protocol is violated. The
victim authorised the wrong device.

Nothing can prevent that outright, so the design narrows it:

- **Ten-minute expiry.** Some implementations allow hours. Nobody legitimately
  takes an hour to type eight letters, and every extra minute is phishing window.
- **The confirmation screen names the application**, and says plainly that a
  *device* is being authorised, with the scopes it will get. That screen is the
  only place a phished person is told what they are actually approving.
- **Refusing is a first-class button**, and refusing says that somebody may have
  tried to phish them.
- **The screen also says so explicitly**: *"Nobody legitimate will ask you to
  enter a code they sent you."*

## The user code

The code is eight characters from a 21-letter alphabet: A–Z without
**B, I, O, S, Z**, and no digits at all. Every exclusion is a misreading people
actually make when they copy a code off a screen across a room: I/1/l, O/0, S/5,
Z/2, B/8.

That is ~35 bits, comfortably past the 20 RFC 8628 §5.1 asks for against a
rate-limited endpoint.

Normalisation forgives case, hyphens, spaces and underscores, and **nothing
else**. A draft mapped "confusable" characters to what the reader supposedly
meant. It rewrote `L`, which *is* in the alphabet, and mapped `Z` to a character
that is not. That silently corrupts a correct code into one that can never match,
producing a failure nobody can reproduce.
`TestNormalizeDoesNotRewriteAlphabetCharacters` now pins the rule.

## Rate limiting, and the counter that was removed

The verification endpoint is rate limited (3/s, burst 10), which is what RFC 8628
§5.1 asks for.

Starting a sign-in is paced too, before anything is stored. A public client gets
60 a minute from one address. A confidential client gets 6,000 a minute, and is
paced as itself once it has authenticated.

Each start is a database row for ten minutes. A public client authenticates
nothing, while its ID is on every device running it. So without this pacing,
anybody could have Signari write as many rows as they liked. Past the limit, the
answer is `429` with `Retry-After`.

A per-record attempt counter was drafted first: `failed_attempts` on the table,
with the record destroyed after five wrong guesses. It was removed before it
shipped, because **it cannot work**. When somebody types a wrong code, there is no
record to charge it to, since Signari cannot know which one they were aiming at.

It would have been a column nothing increments and a function nothing calls. That
is the exact defect this project keeps finding in itself, as [security
scanning](security-scanning.md) describes.

## What is checked, in what order

Order matters here, and getting it wrong was a real bug in the first version.

The client ID is verified **inside the polling transaction, before anything is
consumed**. Originally the caller checked it *after* `PollDeviceCode`, which marks
an approved code redeemed. So anyone holding a leaked device code could present
any client ID and have the approval burned. The legitimate device was then left
stuck on `expired_token` forever: a denial of service against a completed sign-in.

The full order: client ID → expiry → already-redeemed → polling interval →
status.

The polling interval is checked *before* the status. So a device that hammers the
endpoint is slowed whether or not the person has approved yet. Checking it after
would apply the rule only to the boring case.

`slow_down` adds five seconds to the stored interval and persists it, per RFC 8628
§3.5. So the requirement is real, rather than a suggestion the application may
ignore.

## The client must be registered for the grant

This was found while wiring OpenID for Verifiable Credential Issuance (OID4VCI,
see [OID4VCI](oid4vci.md)), which needed the same check: **the device grant was
gated nowhere.**

RFC 6749 §5.2 names the error for it. `unauthorized_client` is *"The
authenticated client is not authorized to use this authorization grant type"*.
Three grants were gated individually:

- `authorization_code` inside `oauth.ValidateCodeRedemption`;
- `client_credentials` and `refresh_token` in their handlers.

The device grant was gated in none of them. So any registered application could
run a device flow, whatever it was registered for. The column default,
`{authorization_code,refresh_token}`, does not include it. So this was not a case
of the registration being permissive: it was not consulted.

Gating each grant inside the handler that happens to serve it is how one gets
missed. So the check now lives in one place that every grant passes through, plus
the device **authorization** endpoint.

Both are needed. The token-endpoint check alone would let an application that may
not finish a device flow still start one. It could therefore still display a code
to a person, and ask them to approve it. That is where a device flow's phishing
value actually is.

Token exchange is excluded from the shared check on purpose. It is authorised by
its own `may_exchange` column, together with the audiences the client may
exchange *for*, which a grant-type list cannot express.

To register the device grant for an application, alongside the authorization code
grant, run:

```sh
signari client set-grants -client-id <id> \
  -grant-types authorization_code,urn:ietf:params:oauth:grant-type:device_code
```

## Verified end to end

These requests were made against a running Signari, and each got the answer
shown:

| | |
|---|---|
| poll before approval | `authorization_pending` |
| poll again immediately | `slow_down` |
| **another client presents the code** | `invalid_grant`, nothing consumed |
| unknown device code | `expired_token` |
| type the code signed in | confirmation naming **Group Test (grouptest)**, scopes `openid`, `profile` |
| approve, then poll | tokens issued |
| **replay the same device code** | `expired_token` — single use |

The ID token was checked rather than assumed:

- `sub` matches the person who approved;
- `amr`, the methods they signed in with, is `["pwd"]`, which is truthfully what
  they did;
- `sid` binds it to the browser session that granted it.

## Single credential path

Tokens are minted through `mintSet`, the same function every other grant uses. So
a device grant gets the same Demonstrating Proof of Possession ([DPoP](dpop.md))
binding, [resource indicators](resource-indicators.md), group claims and audit
trail. A second minting path would be a second place for those to be
forgotten.

Unknown, expired and already-redeemed device codes all answer `expired_token`.
Telling a caller their code was once real narrows a guess.

Abandoned authorizations are swept by the janitor, Signari's clean-up job, an hour
after expiry. Each row holds two code hashes, and a television sign-in nobody
finished should not leave them behind.
