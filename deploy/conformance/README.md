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
| **Basic OP** (`oidcc-basic-certification-test-plan`) | All 36 modules run. **1607 conditions passed, 1 failure, 5 warnings.** 20 PASSED, 4 SKIPPED (unsupported optional features), 5 WARNING, 5 incomplete, 1 FAILED. |

Neither is a vacuous green. The Config OP plan, run against the same engine over
plaintext HTTP, produced **7 failures**; it detects real problems and stopped
finding them once the real problems were fixed.

The Basic OP number moved as each cause was fixed, which is the useful part:

| | conditions passed | failures |
|---|---|---|
| with the suite's own browser automation | 0 modules completed at all | — |
| front channel driven externally | 1472 | 10 |
| one session per module, consent answered | 1628 | 3 |
| `prompt=login` fixed | 1581 | 3 |
| request objects refused | **1607** | **1** |

(Totals vary by a few dozen between runs: modules that need two authorization
rounds sometimes lose the shared `alias` to the next module. The failure count
does not move with it.)

### Two genuine defects it found in the engine

**`prompt=login` looped forever.** `SessionSufficient` returned `StepUpForced`
for it unconditionally, and the sign-in handler resumed by replaying the
authorization query verbatim — `prompt=login` included. A correct password
produced the sign-in form again, and again. No relying party using `prompt=login`
could ever complete authentication. Fixed in `resumeAfterSignIn`, which consumes
the prompt values the sign-in has just satisfied (`login`, `select_account`) and
leaves `consent` alone. Locked down by
`TestSignInConsumesTheReauthPromptItSatisfied`.

**A request object was ignored rather than refused.** Discovery advertises
`request_parameter_supported: false`, but nothing read or rejected the parameter,
so an authorization carrying a `request` object proceeded on the query parameters
instead — silently discarding the integrity protection the client had asked for.
The suite reported it as a missing `state` and a mismatched nonce, several steps
from the cause. `ValidateAuthz` now answers `request_not_supported` /
`request_uri_not_supported` over the redirect, per OIDC Core 6.1/6.2, and the
module reports SKIPPED with zero failures because the feature is now honestly
declined. Locked down by `TestARequestObjectIsRefusedRatherThanIgnored`.

Both were invisible to every test in this repository: they all sign in first, and
none of them sends a parameter the server does not implement.

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

## The suite's browser driver, and how to get round it

The suite hardcodes HtmlUnit: `BrowserControl.java:312` constructs a
`ResponseCodeHtmlUnitDriver` with no configuration to substitute a real browser
or a remote WebDriver. HtmlUnit intermittently fails to run the JavaScript on the
suite's **own** callback page — the page whose only job is to POST
`window.location.hash` to an implicit submit URL — so a module reaches the
callback and then sits in WAITING forever:

    CreateRandomImplicitSubmitUrl :: Created random implicit submission URL
    WebRunner                     :: Completed processing of webpage
    ... then WAITING, indefinitely

With browser automation configured, this capped the plan at zero completed
modules.

The way through is to configure **no** `browser` block at all. `goToUrl` then
publishes each URL for external interaction ("If there is no matching element,
the url is made available for user interaction"), and something without a
JavaScript engine can do the three things the page needed: submit the sign-in
form, answer consent, and make that one POST by hand. `browserdrive.py` does
exactly that against `GET /api/runner/browser/{id}`.

Four things it has to get right, each of which a real browser does silently:

- **HTML-unescape hidden inputs.** `authz` carries the whole authorization query,
  so inside an attribute every separator is `&amp;`. Posting the raw text back
  makes the engine redirect to a URL whose second parameter is named `amp;nonce`
  — which looks like the server emitting a malformed `Location`.
- **Unescape the implicit submit URL.** Thymeleaf inlines it as a JS string
  literal, so every `/` arrives as `\/`.
- **Send `decision=allow` on consent.** It is carried by the submit *button*, not
  by a hidden input, so posting only the hidden fields sends no decision and the
  engine answers `access_denied` — which reads as "the user declined" rather than
  "the harness forgot to click". The consent form also emits one `scope` input
  per scope, so the fields must be a list, not a map.
- **One session per module, not per URL.** A module that authorizes twice needs
  the cookie from the first round; throwing it away makes `auth_time` change and
  `oidcc-max-age-10000` fail on `CheckIdTokenAuthTimeClaimsSameIfPresent` — an
  engine defect that is really the harness discarding the session.

A red herring worth recording: `org.htmlunit.ScriptException: syntax error ...
bootstrap.min.js` is HtmlUnit failing to parse Bootstrap on the **suite's own**
results page, and `setThrowExceptionOnScriptError(false)` means it is logged and
ignored.

## What is still not green, and why

- **`oidcc-server-client-secret-post`** fails `GetStaticClientConfiguration`
  ("the test configuration must contain a client configuration") even though the
  logged config plainly contains one. Not diagnosed. Certifying
  `client_secret_post` is normally a separate plan run with a client configured
  for that method, which is the next thing to try.
- A handful of modules can still be INTERRUPTED by an alias conflict if the
  driver's per-module budget expires before a two-round module finishes — every
  module in a plan shares `alias`, so the next one claims it. The budget is 320s
  for that reason; raising it trades wall-clock for reliability.

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
