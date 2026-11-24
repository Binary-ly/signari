# Proving back-channel logout works

## Introduction

When Ada signs out, Signari tells each of her applications from server to server.
It sends a signed token, the `logout_token`, to an address the application
registered. This is OpenID Connect's "back-channel logout", described in [signing
out](logout.md). If an
application accepts that token without checking it, the session it was meant to
end lives on, and nobody notices.

`signari logout-test` checks an application's back-channel address for you. It
sends one valid token and nine faulty ones, and reports which of the faulty
ones the application accepted. You run it against one application at a time.

## Running the check

Give the command the application's back-channel address, its client ID and the
issuer the application expects:

```sh
signari logout-test -rp-url https://app.example.com/backchannel-logout \
  -client-id app -issuer https://auth.example.com
```

In this example, `-rp-url` is the address the application registered for
back-channel logout, its `backchannel_logout_uri`. When you leave out `-issuer`,
the command uses the issuer in `SIGNARI_ISSUER`.

## The check everyone runs, and why it proves nothing

Back-channel logout is the part of OpenID Connect (OIDC) that most often does not
work, and it fails silently in both directions. The identity provider records a
200 and considers the session ended. The application returns that 200 from a
handler that parsed nothing, verified nothing and deleted nothing. Every
dashboard is green, and the session is still alive.

Delivering a valid `logout_token` and getting a 200 back is therefore close to
meaningless. An endpoint that returns 200 unconditionally passes it.

What separates a working application from a decorative one is whether it
**refuses** what it should refuse.

## What this sends

The command sends one valid token, then nine that are each wrong in exactly one
way:

| Probe | What accepting it means |
|---|---|
| wrong audience | any client's logout token ends this application's sessions |
| wrong issuer | a token from another identity provider ends sessions here |
| no `events` claim | an ID token can be replayed as a logout |
| `events` without the logout event | a token for some other event ends a session |
| contains a `nonce` | prohibited precisely so an ID token cannot be presented as one |
| expired | the replay window never closes |
| neither `sub` nor `sid` | success is reported for a logout that ended nothing |
| broken signature | anyone who can reach the endpoint can end any session |
| replayed `jti` | a captured token can be used again |

A "claim" is one statement inside a token (see the [glossary](glossary.md#claim)).
In a `logout_token`, `sub` names the person, `sid` names the session, and `jti` names
the token itself.

## What it looks like

An application that returns 200 to everything, as a great many of them do, gets
this result:

```
  [ok  ] a valid logout token               HTTP 200
  [FAIL] wrong audience                     HTTP 200
         expected the endpoint to refuse it. accepting this means any client's
         logout token ends this application's sessions
  [FAIL] broken signature                   HTTP 200
         expected the endpoint to refuse it. accepting this means anyone who can
         reach the endpoint can end any session, with no key material at all
  …
  1 passed, 9 failed
```

An application that verifies properly gets this result:

```
  [ok  ] a valid logout token               HTTP 200
  [ok  ] wrong audience                     HTTP 400
  [ok  ] broken signature                   HTTP 400
  …
  10 passed, 0 failed
```

The command exits non-zero on any failure, so it belongs in continuous
integration (CI).

## What it cannot tell you

**Only that the token was accepted or refused.** An application that validates
everything correctly and then forgets to delete the session passes every check
here. That limitation is printed with the results, rather than left for somebody
to assume otherwise.

## Tokens are signed with the real key

The command signs its tokens with the instance's own active signing key. RS256
(RSA with SHA-256) is preferred, falling back to ES256 (ECDSA with SHA-256). See
[key rotation](key-rotation.md) for both.

A back-channel logout endpoint is exactly the kind of lightly-maintained code path most likely
to support only RS256. Testing with a key it cannot verify would report a failure
that is Signari's rather than the application's.
