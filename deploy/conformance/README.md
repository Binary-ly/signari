# OIDF conformance testing

Everything else in this repository is verified by tests written from the same
reading of the specifications that produced the implementation. If that reading
is wrong, the tests are wrong in the same direction and agree with each other.
The `interop/` checks break part of that circle by verifying tokens with an
independent JOSE library; this breaks the rest, by having a third party drive the
protocol and judge the answers.

## What the plans actually test

- **Basic OP** — the authorization code flow end to end, plus the negative cases:
  code exchange, ID token signature and claims (`iss`, `aud`, `exp`, `iat`,
  `nonce`, `at_hash`), UserInfo, scope handling, redirect-URI validation,
  `state`/`nonce` echo, and error responses.
- **Config OP** — the discovery document. This is where implementations usually
  fail, and always for the same reason: **the metadata claims something the server
  does not enforce.** Advertising `S256` without requiring it, or listing a
  signing algorithm with no active key, passes a unit test and fails here.
- **Form Post OP** — `response_mode=form_post`.

## Networking, which is the part that bites

The suite runs inside the container runtime. An engine listening on the macOS
host at `localhost:8099` is unreachable from it.

Worse, this cannot be papered over with port forwarding, because **relying
parties compare the issuer byte-for-byte**. The issuer in our discovery document
must be exactly the URL the suite will use to reach us. That is why
`docker-compose.yml` gives the engine the network alias `signari-engine` and the
issuer is set to match it, rather than to `localhost`.

This is the same trap flagged back in iteration 4, when the dev issuer
(`https://localhost:8080`) did not match the dev listen address
(`127.0.0.1:8099`). Harmless in a curl script; fatal to a real relying party.

## Two clients, not one

Several Basic OP tests need a second client to prove that a code issued to one
client cannot be redeemed by another. `setup.sh` registers both, with the
suite's callback URLs:

    https://localhost:8443/test/a/signari/callback
    https://localhost:8443/test/a/signari/callback?dummy1=lorem&dummy2=ipsum

The second is not a typo. The suite deliberately tests a redirect URI carrying
query parameters, because implementations that "helpfully" normalise or strip
them get it wrong. Our matcher is byte-for-byte string equality, so both must be
registered verbatim.

## Expected failures on the first run

Recorded honestly, so a red result is read correctly rather than explained away:

- **`request_parameter_supported`** — JAR is not implemented. Discovery advertises
  `false`, so the relevant tests should skip rather than fail. If they fail, the
  metadata and the server disagree, which is precisely the bug Config OP exists
  to find.
- **Dynamic client registration** — not implemented. The plan variant must be set
  to static client registration.
- **`prompt=none`** — implemented, but only the no-session case is exercised so
  far; the has-session path returns a code and has not been tested by a third party.
- **`offline_access`** — implemented; refresh rotation is covered by our own
  end-to-end tests but not yet by the suite.

## Running

    ./setup.sh    # bring up the stack, register both clients, print the config
    ./run.sh      # execute the plan via scripts/run-test-plan.py


## Where this got to, and the honest limit

The engine's side of the flow is **verified working** by the suite's own log:

    Incoming HTTP request to /test/a/signari/callback
    url: .../callback?code=q_qz6FNQpPQqVbenkjBlt4FLwmeJFxaCYah239U-yyE&iss=https%3A%2F...

We issue a valid authorization code carrying `iss` (RFC 9207) to a registered
redirect URI, and the suite receives it. 721 conditions passed across 36 modules.

Two blockers were found and one was fixed:

1. **FIXED -- alias conflict.** `run-test-plan.py` parallelises by default, and every
   module in a plan shares `alias: signari`, so each new module interrupted the previous
   one. **Use `--no-parallel`.** This accounted for ~30 of the INTERRUPTED results.

2. **NOT FIXED -- the suite's WebRunner stalls after the callback.** With serial
   execution the module still sits in WAITING after
   "Created random implicit submission URL" / "Completed processing of webpage".
   The browser never returns to submit. The suite hardcodes `HtmlUnitDriver`
   (`BrowserControl.java:312`, a `ResponseCodeHtmlUnitDriver` subclass) with no
   configuration to substitute a real browser.

   The logged JavaScript error is a red herring worth recording so nobody chases it:

       org.htmlunit.ScriptException: syntax error
         (https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js#6)

   That is HtmlUnit failing to parse Bootstrap on the SUITE'S OWN results page, and
   `setThrowExceptionOnScriptError(false)` means it is logged and ignored.

**Recommended next step:** stop building the suite locally. Use the OIDF's hosted
instance at https://www.certification.openid.net against a publicly reachable
deployment of the engine. Local self-hosting of the suite is supported but the
browser automation is the fragile part, and certification requires a public
deployment anyway.


## Re-checked, August 2026: is our page the reason the driver stalls?

The blocker above is the suite's HtmlUnit driver, and it was worth asking whether
we were contributing to it. We are not, and the check produced something else.


**What the check did find** is a control that was inert without script. The
passkey button is `type="button"`, so it does nothing on its own, and
`passkey.js` only ever attached a click listener to it — it never revealed it. A
visitor with scripting off, or on a browser without WebAuthn, saw a button that
did nothing when pressed. `passkeyjs.go` carries a comment explaining that inline
`onclick` handlers were avoided precisely because a CSP would leave "a button
that silently does nothing"; the same outcome had been reached by a different
route. The row is now `hidden` in the markup and revealed by the script only when
`PublicKeyCredential` exists.

**On automating the suite**: the OpenID Foundation does publish a Python driver
for CI use, and `run.sh` already invokes it (`scripts/run-test-plan.py`). It is
not the missing piece — the stall is inside the suite's own browser automation,
downstream of that script. The recommendation below is unchanged.
