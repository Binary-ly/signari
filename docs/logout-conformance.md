# Proving back-channel logout works

```sh
signari logout-test -rp-url https://app.example.com/backchannel-logout \
  -client-id app -issuer https://auth.example.com
```

## The check everyone runs, and why it proves nothing

Back-channel logout is the part of OpenID Connect that most often does not work,
and it fails silently in both directions. The identity provider records a 200 and
considers the session ended. The application returns that 200 from a handler that
parsed nothing, verified nothing and deleted nothing. Every dashboard is green
and the session is still alive.

Delivering a valid logout token and getting a 200 back is therefore close to
meaningless — an endpoint that returns 200 unconditionally passes it.

What separates a working relying party from a decorative one is whether it
**refuses** what it should refuse.

## What this sends

One valid token, then nine that are each wrong in exactly one way:

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

## What it looks like

A relying party that returns 200 to everything — which is a great many of them:

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

One that verifies properly:

```
  [ok  ] a valid logout token               HTTP 200
  [ok  ] wrong audience                     HTTP 400
  [ok  ] broken signature                   HTTP 400
  …
  10 passed, 0 failed
```

It exits non-zero on any failure, so it belongs in CI.

## What it cannot tell you

**Only that the token was accepted or refused.** A relying party that validates
everything correctly and then forgets to delete the session passes every check
here. That limitation is printed with the results rather than left for somebody
to assume otherwise.

## Tokens are signed with the real key

RS256 is preferred, falling back to ES256. A logout endpoint is exactly the kind
of lightly-maintained code path most likely to support only RS256, and testing
with a key it cannot verify would report a failure that is ours rather than
theirs.
