# CAPTCHA

Off by default. Adaptive when on.

```sh
SIGNARI_CAPTCHA_MODE=adaptive          # off (default) | adaptive | always
SIGNARI_CAPTCHA_PROVIDER=turnstile     # turnstile | hcaptcha | recaptcha
SIGNARI_CAPTCHA_SITE_KEY=...
SIGNARI_CAPTCHA_SECRET=...
SIGNARI_CAPTCHA_AFTER_FAILURES=3       # adaptive threshold, per source address
SIGNARI_CAPTCHA_FAIL_CLOSED=1          # optional; see below
```

## Why off by default

A CAPTCHA is a tax on real users. It is paid by everybody, every time, to
inconvenience a population that increasingly solves them more reliably than
people do — and it falls hardest on someone using a screen reader, an old
browser, or a connection that looks unusual.

So it is a decision an operator makes, not a default they inherit.

## Adaptive is the mode worth having

A person signing in normally **never sees a challenge**. A script working through
a password list sees one after a handful of attempts from the same address.

Failures are counted per source address, in memory, over a fifteen-minute window.
A correct password clears that address — the next person behind an office NAT
should not inherit a challenge from a colleague who mistyped.

Failures are counted for **every** rejected sign-in, including ones where no such
account exists. Counting only real accounts would make the appearance of a
challenge an oracle for which usernames are worth guessing.

### What adaptive does not do

It does not stop a distributed attack. An attacker with a pool of addresses gets
a fresh allowance from each, and that is a real limit rather than an oversight.
What bounds the distributed case is the per-account throttle and the global rate
limit in front of Argon2 — neither of which depends on this.

Stated plainly so nobody mistakes this for more than it is.

## Checked before the password

The challenge is verified **before** the credential lookup, so a solved challenge
is a precondition for spending an Argon2 evaluation rather than a second opinion
afterwards.

A failed challenge also counts as a login failure. Otherwise an attacker could
hold an address's counter still by submitting blank challenges forever, and
adaptive mode would never escalate.

## Fail open, by default

When the provider cannot be reached, the sign-in proceeds and the failure is
logged. `SIGNARI_CAPTCHA_FAIL_CLOSED=1` reverses that.

This check sits **in front of** a password, not instead of one. Failing open
degrades to exactly the posture of having no CAPTCHA. Failing closed turns
somebody else's outage into a total authentication outage on an identity
provider — which is a defensible choice, and should be the operator's.

## The CSP cost, paid only where it is owed

A challenge widget is third-party script running on the sign-in page — the one
page where an injection is worth most. The Content-Security-Policy is therefore
widened **only when a challenge is configured**, and only to that provider's own
origins:

```
off:      script-src 'self'
turnstile: script-src 'self' https://challenges.cloudflare.com
```

A blanket relaxation would leave the hole open for every deployment, including
the ones that never turn this on.

## Misconfiguration refuses to start

```
SIGNARI_CAPTCHA_MODE=adaptative
  -> unknown captcha mode "adaptative": use off, adaptive or always

SIGNARI_CAPTCHA_MODE=adaptive, no keys
  -> SIGNARI_CAPTCHA_MODE is "adaptive" but SIGNARI_CAPTCHA_SITE_KEY or
     SIGNARI_CAPTCHA_SECRET is missing; a challenge with no keys renders an
     empty box and refuses every sign-in
```

A typo that silently disables a security control is the worst outcome available:
the operator believes they have something they do not. Both are refused at
startup.

## A bug the existing tests caught

`SiteKey()` and `Provider()` were not nil-safe, while every other method was. The
login renderer reads both on **every** request whether or not a challenge is
configured — so the sign-in page panicked on any deployment without one, which is
the default and therefore almost all of them.

"The caller should check first" was never going to hold for a value read on every
render. Both are nil-safe now, and a test asserts it rather than the comment
claiming it.

## Verified

| | |
|---|---|
| default (off) | page renders, no widget, `script-src 'self'` |
| `always` | Turnstile widget with the site key, CSP widened to Cloudflare only |
| sign-in with no response | refused: "That challenge was not completed" |
| unsolved response | refused by the provider |
| provider unreachable | sign-in proceeds (fail open), logged |
| `FAIL_CLOSED=1`, unreachable | refused |
| misspelled mode or provider | refuses to start |
