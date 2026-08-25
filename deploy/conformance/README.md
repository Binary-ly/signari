# OIDF conformance testing

Everything else in this repository is verified by tests written from the same
reading of the specifications that produced the implementation. If that reading
is wrong, the tests are wrong in the same direction and agree with each other.
The `interop/` checks break part of that circle by verifying tokens with an
independent JOSE library; this breaks the rest, by having a third party drive the
protocol and judge the answers.

## Current state, measured 25 August 2026

| Plan | Result |
|---|---|
| **Config OP** (`oidcc-config-certification-test-plan`) | **PASSED** — 39 conditions, 0 failures, 0 warnings, runner exit 0. Reproduced twice. |
| **Basic OP** (`oidcc-basic-certification-test-plan`) | Engine side verified: `oidcc-server` ran to completion, 99 log entries, **0 failures**. The plan does not finish — see "the suite's browser driver" below. |

The Config OP pass is not a vacuous green. The same plan, run against the same
engine over plaintext HTTP, produced **7 failures** (every endpoint check plus
`CheckDiscEndpointAllEndpointsAreHttps`). It detects real problems; it stopped
finding them once the real problems were fixed.

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

## Four things that had to be right, none of which failed loudly

Each of these was found by running the suite, and each produced a symptom that
pointed somewhere else.

**The issuer must be HTTPS.** OIDC requires it for the issuer and every endpoint
derived from it. With `http://` the discovery checks fail one after another and
it reads like seven separate bugs; it is one.

**The redirect URI must be the suite's own base URL.** The suite serves itself at
`https://localhost.emobix.co.uk:8443` — a public DNS name that resolves to
127.0.0.1, set in its `docker-compose.yml` as `--fintechlabs.base_url`. Registering
`https://localhost:8443/...` looks right and matches nothing, so every Basic OP
module dies on `redirect_uri is not registered for this client`.

**Two callbacks, not one twice.** Several modules need the query-parameter variant

    https://localhost.emobix.co.uk:8443/test/a/signari/callback
    https://localhost.emobix.co.uk:8443/test/a/signari/callback?dummy1=lorem&dummy2=ipsum

The second is not a typo. The suite deliberately tests a redirect URI carrying
query parameters, because implementations that "helpfully" normalise or strip
them get it wrong. Our matcher is byte-for-byte equality, so both must be
registered verbatim. An earlier version of `setup.sh` looped twice over the same
URI and never registered the variant at all.

**PKCE has to be optional for these two clients.** Clients default to
`require_pkce`, per RFC 9700 and OAuth 2.1. The OIDC Basic profile predates that
rule and sends no challenge, so a client demanding one refuses every
authorization request with `code_challenge is required` — and the browser lands
on an error page, which surfaces as the misleading
`Unable to locate element with ID: 'u'`.

`client create -require-pkce=false` scopes the exception to the client being
certified. It is a property of the profile, not a weakening of the default: every
other client still gets `require_pkce = true`, and
`TestPKCEIsRequiredByDefaultInBothPlaces` fails the build if either the flag
default or the column default moves.

## Networking, which is the part that bites

The suite runs inside the container runtime. An engine listening on the macOS
host at `localhost:8099` is unreachable from it. This cannot be papered over with
port forwarding, because **relying parties compare the issuer byte-for-byte** —
so `docker-compose.yml` gives the engine the network alias `signari-engine` and
the issuer is set to match.

The suite is a JVM, so it will not trust a private CA until the certificate is in
the truststore **and the process has restarted**; a JVM reads the truststore once,
at startup. `setup.sh` does both.

## The suite's browser driver, which is the remaining limit

With everything above fixed, `oidcc-server` runs to completion with zero
failures — the full code flow, ID token, `at_hash` and UserInfo, all judged by a
third party. The plan still does not finish, because modules stall after the
callback:

    CreateRandomImplicitSubmitUrl :: Created random implicit submission URL
    WebRunner                     :: Completed processing of webpage
    ... then WAITING, indefinitely

The browser never navigates to the submission URL. This is in the suite, not in
the engine: `BrowserControl.java:312` constructs a `ResponseCodeHtmlUnitDriver`
unconditionally, and there is no configuration to substitute a real browser or a
remote WebDriver. It is also intermittent — the same module completes on one run
and stalls on the next, which is why a green module is worth more than a red plan
here.

Two red herrings worth recording so nobody chases them:

- `org.htmlunit.ScriptException: syntax error ... bootstrap.min.js` is HtmlUnit
  failing to parse Bootstrap on the **suite's own** results page.
  `setThrowExceptionOnScriptError(false)` means it is logged and ignored.
- Adding a trailing `"Verify Complete"` task to the browser config makes the stall
  *more* frequent, not less: the driver stops at the callback instead of following
  the implicit submit URL. The sign-in task alone, marked `"optional": true` so a
  module needing no login is skipped rather than failed, is the best local
  configuration found.

## Running

    ./setup.sh    # TLS, engine, clients, user, CA into the suite truststore
    ./run.sh      # execute the plan via scripts/run-test-plan.py

The runner needs `httpx` and `pyparsing` (`scripts/requirements.txt`), and for a
local suite with no authentication, `CONFORMANCE_DEV_MODE=1` and
`DISABLE_SSL_VERIFY=1`. Always pass `--no-parallel`: every module in a plan shares
`alias: signari`, so parallel modules interrupt each other.

## Certification itself

Passing the plans is the engineering half and is what these files are for. Being
*listed* as certified is a separate, administrative act: it needs an account on
the OpenID Foundation's site, a publicly reachable deployment, a submitted set of
test logs, a fee, and a signed declaration of conformance by someone able to make
it on behalf of the project. None of that can be done from this repository.
