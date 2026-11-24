# CAPTCHA

## Introduction

Some sign-in attempts come from scripts working through lists of passwords, not
from people. A CAPTCHA (Completely Automated Public Turing test to tell
Computers and Humans Apart) is a challenge meant to tell a person from a script.

Signari's CAPTCHA is off by default, and adaptive when on. A person signing in
normally never sees a challenge. A script sees one after a handful of failed
attempts.

You turn it on with the `SIGNARI_CAPTCHA_` environment variables on this page.
[Every environment variable](configuration.md) lists them all.

## Turning it on

These settings turn on adaptive challenges from a hosted provider:

```sh
SIGNARI_CAPTCHA_MODE=adaptive          # off (default) | adaptive | always
SIGNARI_CAPTCHA_PROVIDER=turnstile     # turnstile | hcaptcha | recaptcha | siteverify
SIGNARI_CAPTCHA_SITE_KEY=...
SIGNARI_CAPTCHA_SECRET=...
SIGNARI_CAPTCHA_AFTER_FAILURES=3       # adaptive threshold, per source address
SIGNARI_CAPTCHA_FAIL_CLOSED=1          # optional; see below
```

In this example, a challenge appears after three failures from one address.
`SIGNARI_CAPTCHA_FAIL_CLOSED` is explained under
[Fail open, by default](#fail-open-by-default).

## A service you run yourself

`siteverify` is for a challenge service of your own. Then sign-in does not
depend on a third party, or send it the addresses of your people.

Your service has to speak the same shape as the others. It receives a POST of
`secret`, `response` and `remoteip`. It answers with JSON carrying a `success`
boolean and optionally `error-codes`. Point Signari at it with four more
settings:

```sh
SIGNARI_CAPTCHA_PROVIDER=siteverify
SIGNARI_CAPTCHA_VERIFY_URL=https://captcha.example.com/siteverify
SIGNARI_CAPTCHA_WIDGET_URL=https://captcha.example.com/widget.js
SIGNARI_CAPTCHA_WIDGET_CLASS=my-captcha
SIGNARI_CAPTCHA_RESPONSE_FIELD=my-captcha-response
```

All four are required, and both addresses must be https, since the verify
address receives the secret. Setting them with any other provider stops Signari
from starting, instead of being ignored.

The page renders `<div class="my-captcha" data-sitekey="…">` and loads the
script. Only the script's origin joins the Content Security Policy (CSP), the
browser rule that says where a page may load scripts from. A widget that calls
anywhere else needs a [theme](theming.md) with that written in.

The verify address goes through the outbound guard. So a service on a private
address has to be named in `SIGNARI_OUTBOUND_ALLOW_PRIVATE`.

## Why off by default

A CAPTCHA is a tax on real people. Everybody pays it, every time, to
inconvenience a population that increasingly solves them more reliably than
people do. It falls hardest on someone using a screen reader, an old browser, or
a connection that looks unusual.

So it is a decision an administrator makes, not a default they inherit.

## Adaptive is the mode worth having

A person signing in normally **never sees a challenge**. A script working
through a password list sees one after a handful of attempts from the same
address.

Failures are counted per source address, in memory, over a fifteen-minute
window. A correct password clears that address. Many people in an office can
share one address, through network address translation (NAT). The next person
behind it should not inherit a challenge from a colleague who mistyped.

Failures are counted for **every** rejected sign-in, including ones where no
such account exists. Counting only real accounts would make the appearance of a
challenge an "oracle": a signal for which usernames are worth guessing.

### What adaptive does not do

It does not stop a distributed attack. An attacker with a pool of addresses gets
a fresh allowance from each, and that is a real limit, not an oversight.

What bounds the distributed case is the per-account throttle, and the global
rate limit in front of Argon2, the function that checks passwords. Neither of
them depends on this.

This is stated plainly, so that nobody mistakes this check for more than it is.

## Checked before the password

The challenge is verified **before** the credential lookup. So a solved
challenge is a precondition for spending an Argon2 evaluation, not a second
opinion afterwards.

A failed challenge also counts as a sign-in failure. Otherwise an attacker could
hold an address's counter still by submitting blank challenges forever, and
adaptive mode would never escalate.

## Fail open, by default

When the provider cannot be reached, the sign-in proceeds and the failure is
logged. `SIGNARI_CAPTCHA_FAIL_CLOSED=1` reverses that.

This check sits **in front of** a password, not instead of one. Failing open
degrades to exactly the posture of having no CAPTCHA. Failing closed turns
somebody else's outage into a total authentication outage on an identity
provider. That is a defensible choice, and it should be the administrator's.

## The CSP cost, paid only where it is owed

A challenge widget is third-party script running on the sign-in page, the one
page where an injection is worth most. So the Content-Security-Policy is widened
**only when a challenge is configured**, and only to that provider's own
origins:

```
off:      script-src 'self'
turnstile: script-src 'self' https://challenges.cloudflare.com
```

A blanket relaxation would leave the hole open for every deployment, including
the ones that never turn this on.

## Misconfiguration refuses to start

Signari refuses to start when these settings are wrong. Here are two mistakes,
each with the message it gives:

```
SIGNARI_CAPTCHA_MODE=adaptative
  -> unknown captcha mode "adaptative": use off, adaptive or always

SIGNARI_CAPTCHA_MODE=adaptive, no keys
  -> SIGNARI_CAPTCHA_MODE is "adaptive" but SIGNARI_CAPTCHA_SITE_KEY or
     SIGNARI_CAPTCHA_SECRET is missing; a challenge with no keys renders an
     empty box and refuses every sign-in
```

A typo that silently disables a security control is the worst outcome
available: the administrator believes they have something they do not. Both are
refused at startup.

## A bug the existing tests caught

`SiteKey()` and `Provider()` were not nil-safe, while every other method was.
Being "nil-safe" means a method works even when no challenge is configured. The
sign-in page renderer reads both on **every** request, whether or not a
challenge is configured. So the sign-in page panicked on any deployment without
one, which is the default and therefore almost all of them.

"The caller should check first" was never going to hold for a value read on
every render. Both are nil-safe now, and a test asserts it, instead of a comment
claiming it.

## Verified

Each of these cases was checked:

| | |
|---|---|
| default (off) | page renders, no widget, `script-src 'self'` |
| `always` | Turnstile widget with the site key, CSP widened to Cloudflare only |
| sign-in with no response | refused: "That challenge was not completed" |
| unsolved response | refused by the provider |
| provider unreachable | sign-in proceeds (fail open), logged |
| `FAIL_CLOSED=1`, unreachable | refused |
| misspelled mode or provider | refuses to start |
