# OIDF conformance testing

Everything else in this repository is verified by tests written from the same
reading of the specifications that produced the implementation. If that reading
is wrong, the tests are wrong in the same direction and agree with each other.
The `interop/` checks break part of that circle by verifying tokens with an
independent JOSE library; this breaks the rest, by having a third party drive the
protocol and judge the answers.

## Current state, measured 3 November 2026

Against the suite as of its commit `6b8b809` (7 August 2026), from nothing: a fresh
suite, `setup.sh`, then each plan below in one run. Static clients throughout.

| Plan | Result |
|---|---|
| **Config OP** (`./run.sh config`) | 2 modules, **44 conditions, 0 failures, 0 warnings**, runner exit 0. |
| **Basic OP** (`./run.sh basic`) | 36 modules, **1737 conditions, 0 failures, 5 warnings**, the five below. 81 seconds. An earlier run the same day counted 1712; the count moves by a few dozen between runs, the failures did not. |
| **Form Post OP** (`./run.sh formpost`) | 36 modules, **1877 conditions, 0 failures, 5 warnings**, the same five. |
| **RP-Initiated Logout OP** (`./run.sh rp-logout`) | 12 modules, **555 conditions, 0 failures, 0 warnings**, runner exit 0. Eight are REVIEW: the error pages a human is asked to look at. The driver logs where each visit ended (`ended at 400 /oauth2/logout …`) so that the look is possible. |
| **Front-Channel Logout OP** (`./run.sh fc-logout`) | 3 modules, **90 conditions, 0 failures, 0 warnings**, runner exit 0. |
| **Back-Channel Logout OP** (`./run.sh bc-logout`) | 3 modules, **94 conditions, 0 failures, 0 warnings**, runner exit 0: the logout token arrived from the engine and its signature, `iss`, `aud`, `iat`, `jti`, `events` and `sid` were checked. |
| **FAPI 2.0 Security Profile** (`python3 fapiconfig.py /elsewhere/fapi.json; CONFIG=/elsewhere/fapi.json ./run.sh fapi2`: `private_key_jwt`, DPoP, plain FAPI) | 57 modules, **4098 conditions, 1 failure, 4 warnings**: 41 PASSED, 9 REVIEW, 2 SKIPPED, 2 WARNING. The failure is `ensure-pkce-code-verifier-required`: a missing `code_verifier` is answered `invalid_request`, which RFC 6749 §5.2 defines as a request "missing a required parameter", and the suite wants `invalid_grant`; that waits on reading RFC 7636 and OAuth 2.1, which are not in `specs/`. One module more, `par-attempt-to-use-expired-request_uri`, is interrupted rather than failed: it sleeps the pushed request's whole 300 seconds and the runner waits 240. The first run had 48 failures; four defects lay behind them, below. |
| **FAPI 2.0 Message Signing** (`python3 fapiconfig.py --message-signing /elsewhere/fapims.json; CONFIG=/elsewhere/fapims.json ./run.sh fapi2-ms`: signed requests, JARM, DPoP, `private_key_jwt`) | 71 modules, **5524 conditions, 1 failure, 4 warnings**, the first time it was run: 54 PASSED, 9 REVIEW, 3 SKIPPED, 2 WARNING. The failure and the interrupted module are the Security Profile's two above. The skips are the RS256 tests, which do not apply to the ES256 keys the clients have, and refresh, which the clients do not ask for. |
| **OID4VCI issuer** (`python3 fapiconfig.py --vci /elsewhere/vci.json; CONFIG=/elsewhere/vci.json ./run.sh vci`: wallet-initiated, authorization details, SD-JWT VC, DPoP) | 16 modules, **1694 conditions, 0 failures, 0 warnings**: 12 PASSED, 3 SKIPPED (signed metadata, key attestation, credential encryption, none of them configured). The plan is the suite's alpha. Its first run found three defects: a batch of proofs under one `c_nonce` was refused at its second proof, a stale nonce was `invalid_proof` instead of `invalid_nonce`, and a missing proof was `invalid_credential_request` instead of `invalid_proof`. A credential whose `vct` is an `https` URL fails five modules, the suite fetching Type Metadata from it, which this issuer does not serve; the SD-JWT VC draft held here leaves that retrieval at "the consumer's discretion", and the suite's own comment says its stricter reading is being settled with the working group. |
| **Dynamic OP** (`oidcc-dynamic-certification-test-plan[response_type=code]`, registering with a token from `signari registration token`) | **Cannot pass, by design.** 24 modules, 19 failures. OIDC Core §15.2 has every dynamic OP support the `id_token` and `id_token token` response types, and nothing containing `token` crosses the front channel here. Ten more are `code_challenge is required`, the profile sending no PKCE, which a registered client cannot opt out of; two want `request_uri`, which is not supported; one wants `sector_identifier_uri` checked, which registration ignores because a registered client is never pairwise; one waits for an operator to rotate the signing keys mid-test; and the suite registers faster than the per-address limit, which answers 429. Measured once and not scripted. |
| **Hybrid OP** (`./run.sh hybrid`) | 97 modules. **`code id_token`: 34 modules, none failed** (19 PASSED, 5 REVIEW, 5 SKIPPED, 5 WARNING). `code token` and `code id_token token`: 50 failures, every one the authorization endpoint answering `unsupported_response_type`, which is the design: no access token crosses the front channel ([response modes](../../docs/response-modes.md)). The plan cannot pass whole for that reason. |

**What the FAPI 2.0 plan found, the first time it was run.** No authorization code
had ever been bound to a DPoP key: `dpop_jkt`, and a proof on a pushed request, were
read, stored and checked at the token endpoint, and the code was issued without
them, so any key redeemed it. A pushed request was answered `text/plain`, because
the status went out before the type. Userinfo and the credential endpoint took a
FAPI 2.0 client's token behind an RS256 proof, which the profile rules out for
resource servers as well. And a person could not cancel a sign-in at all, so the
application was never told they had said no. All four are fixed. Two modules need
the driver to act as a person would differently, and it does, by name: it cancels
for `user-rejects-authentication`, and for
`par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` it opens the first
page and leaves it.

**What the Hybrid plan found, the first time it was run.** Every fragment response
was encoded twice, so a script reading `location.hash` found `iss` still
percent-encoded and refused the response as a mix-up (RFC 9207). The engine's own
tests decoded twice and agreed with it. A refusal of `code token` went in the
query, where a client that asked for it was not listening. And a redirect URI with
a fragment, which RFC 6749 §3.1.2 forbids, could be registered everywhere but
dynamic registration. All three are fixed.

The August measurement for comparison: Config OP 39 conditions, Basic OP 1754
conditions with one more module PASSED and one fewer SKIPPED. That module is
`oidcc-ensure-request-object-with-redirect-uri`. In August request objects were
refused outright and it passed on the refusal; now they are accepted signed and
only signed, and the suite skips it because `none` is not among
`request_object_signing_alg_values_supported`.

`setup.sh` and `run.sh` had stopped working in the meantime, quietly: `instance
create` no longer makes an organisation, so `bootstrap` does; the compose file
required `SIGNARI_FIRST_EMAIL` of every command, not only the first run; the
runner's `--show-untested-test-modules` takes a value, so it swallowed the plan's
name; and the runner's grammar reads an absolute configuration path as a plan.
`browserdrive.py` posted the fragment without its `#`, which the suite strips, so
`code` arrived as `ode`. A configuration filled with secrets belongs outside this
directory, `CONFIG=/elsewhere/basic.json ./run.sh basic`, so that it is not one
`git add` from being committed.

**Each logout plan sets the clients up for itself.** A front-channel URI registered
while the RP-Initiated plan runs is a request that plan "wasn't expecting", and it
fails; `run.sh rp-logout`, `fc-logout` and `bc-logout` each register their channel
and clear the others first.

**The back channel needed the engine to reach the suite, and its outbound guard is
right to refuse both halves of that.** The suite's nginx serves a self-signed
certificate for `CN=localhost` with no SAN, on a private address. `setup.sh` gives
it a certificate for `localhost.emobix.co.uk`, the name the suite calls itself by,
puts it on the engine's network under that name, and starts the engine trusting that
one certificate (`SIGNARI_CA_BUNDLE`) and allowed to reach that one network
(`SIGNARI_OUTBOUND_ALLOW_PRIVATE`). Nothing else is loosened, and the compose file
passes both through empty otherwise.

Neither is a vacuous green. The Config OP plan, run against the same engine over
plaintext HTTP, produced **7 failures**; it detects real problems and stopped
finding them once the real problems were fixed.

The Basic OP number moved as each cause was fixed, which is the useful part:

| | conditions passed | failures | incomplete |
|---|---|---|---|
| with the suite's own browser automation | 0 modules completed at all | — | 36 |
| front channel driven externally | 1472 | 10 | many |
| one session per module, consent answered | 1628 | 3 | 5 |
| `prompt=login` fixed | 1581 | 3 | 5 |
| request objects refused | 1607 | 1 | 5 |
| placeholders answered, `client_secret_post` client added | 1605 | **0** | 1 |
| `prompt=consent` fixed | **1754** | **0** | **0** |

Wall-clock fell from 1265s to 84s over the same 36 modules, because nothing
stalls any more.

### Three genuine defects it found in the engine

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

**`prompt=consent` looped forever too.** The same defect on the other resume
path, found by `oidcc-refresh-token`. The branch honouring `prompt=consent`
deliberately ignores the stored grant and re-lists every scope — the client asked
the user to look again — so replaying the query after the decision committed
rendered the identical page, and pressing Allow never got anywhere. Both resume
paths now share `consumePrompt`, which drops only what has actually been
satisfied: sign-in consumes `login` and `select_account`, granting consent
consumes `consent`, and neither touches the other's.

All three were invisible to every test in this repository: they all sign in
first, none of them sends a parameter the server does not implement, and none
re-enters the authorization endpoint after answering a prompt.

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

## The five warnings, none of which is a failure

Recorded so a green run is read accurately rather than as "nothing left to do".

- **`oidcc-codereuse-30seconds`** — after a code is replayed, the access token
  already issued from it still works at UserInfo. RFC 6749 section 4.1.2 says the
  server SHOULD revoke all tokens issued from a reused code; refresh-token
  families ARE revoked (`RevokeFamilyForCode`), but this module requests no
  `offline_access`, so there is no family and therefore no grant to revoke.
  Closing it means recording every issued access token's `jti` so it can be
  denied later — `core.revoked_jtis` is a denylist and issuance is stateless
  today. That is a deliberate architectural trade (a write per token issued), not
  a bug to patch quietly.
- **`oidcc-scope-email`, `oidcc-alternate-happy-flow`** — `email` appears in the
  ID token when only the `email` scope was requested and no claims request was
  made. Permitted, but the suite expects code-flow claims to come from UserInfo.
- **`oidcc-scope-profile`, `oidcc-claims-essential`** — `name` and other profile
  claims are absent from UserInfo. The conformance user is created with an email
  and nothing else, so there is nothing to return; give it profile data before
  reading anything into this.

**REVIEW** is not a failure either: it is the status of a module whose screenshot
placeholder was filled, and it means a human should confirm the picture shows
what it should. That is the intended certification workflow.

## Running

    ./setup.sh                                  # TLS, engine, clients, user, CA into the suite truststore
    CONFIG=/elsewhere/basic.json ./run.sh basic # or config, formpost, hybrid, or any plan with its variants

Both honour `DOCKER_CONTEXT`, so the stack can live in a virtual machine of its own
rather than beside whatever else the default one runs.

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
