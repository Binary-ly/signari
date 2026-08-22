# `signari doctor`

```sh
signari doctor           # exit 1 if anything critical is found
```

## Why

Every feature here ships with something that proves that feature works.
`proxy check` proves the forward-auth route is actually protected. `scim verify`
proves a deprovisioned user is gone from the downstream app. `policy test` proves
the rules match their stated intent. Each answers one question well.

None of them answers the question an operator has on the first day, which is **is
this deployment sound**. That question spans configuration nobody checks until it
fails at the worst moment: an issuer served over plaintext, a root key nobody set,
a SAML provider whose logout is silently refused, recovery email that goes to a log
file where nobody will read it.

## Output

Findings first, ranked, each with what is wrong, why it matters, and what to do:

```
  [CRITICAL] issuer          the issuer is plaintext HTTP: every token, code and
                             client secret in the flow crosses the network readable
                             fix: serve over HTTPS and set SIGNARI_ISSUER to the https:// URL

  [CRITICAL] root key        no root key is configured
                             fix: set SIGNARI_ROOT_KEY to base64 of 32 random bytes. It
                             wraps every stored private signing key; without it nothing
                             can be unsealed

  [CRITICAL] logout delivery 364 notice(s) have exhausted their retries and been parked
                             fix: these are logouts and security events that never
                             reached the relying party. Those sessions may still be live
                             at the application. Inspect core.outbox last_error

  [warning ] mail            no SMTP is configured, so account recovery cannot send email

  checked: issuer URL, root key, admin API token, outbound mail, signing keys,
           OAuth clients, SAML service providers, external sign-in providers,
           delivery queue, access policy
  3 critical, 1 warning, 0 info
```

Two properties of that output are deliberate.

**Every finding carries a fix.** A checker that prints `TLS: warning` teaches an
operator to ignore it. There is a test (`TestEveryFindingCarriesAFix`) that fails
if a finding above `info` has no `Fix` line.

**A clean run still prints `checked:`.** "No findings" and "nothing ran" have
looked identical at least three times in this project's own history — gosec
exiting 0 having analysed nothing, `scim verify` reporting agreement it never
tested, an impossible-travel check that only worked because a row had been seeded
by hand. The list of what ran is the difference between a result and silence.

## Exit status

That is the point of the command. Non-zero when anything critical is found, so it
gates a deploy or runs from cron:

```sh
signari doctor || { echo "refusing to deploy"; exit 1; }
```

Verified both ways, without a pipe — a pipe reports the exit status of the last
command in it, which is how two earlier "clean" results in this project were
wrong:

```sh
$ SIGNARI_ISSUER=http://auth.example.com signari doctor >/dev/null 2>&1; echo $?
1
$ SIGNARI_ISSUER=https://auth.signari.dev SIGNARI_ROOT_KEY=... signari doctor >/dev/null 2>&1; echo $?
0
```

Warnings and info do not fail the run. They are things to fix this week, not
reasons to block a release tonight.

## What it checks

| Area | Finding | Severity |
| --- | --- | --- |
| issuer | missing | critical |
| issuer | plaintext `http://` on a real host | critical |
| issuer | plaintext on loopback | info — how everyone develops |
| issuer | trailing slash | warning — `iss` is compared exactly |
| root key | neither `SIGNARI_ROOT_KEY` nor `..._REF` set | critical |
| admin API | token shorter than 32 characters | critical |
| admin API | no token at all | *not a finding* — the API is off unless an address is given |
| mail | no `SMTP_HOST`/`MAIL_FROM` | warning — nobody can recover an account |
| keys | none, or none active | critical |
| keys | no active RS256 | info — SAML needs one, most SPs cannot verify ECDSA |
| clients | plaintext redirect URI on a non-loopback host | critical |
| clients | enabled client not requiring PKCE | warning |
| saml | logout URL registered but no SP certificate | warning — every logout from it is refused |
| federation | generic OIDC provider allows sign-up with untrusted email verification | info — sign-up will always refuse |
| outbox | notices parked after exhausting retries | critical — sessions may still be live downstream |
| policy | none in force | info — everything is open, which may be correct |
| theme | `SIGNARI_THEME_DIR` unreadable | critical — every page is silently the built-in one |
| theme | a page override was refused | warning — that page is correct and working, and is not yours |
| theme | the directory overrides nothing | warning — usually a filename that does not match a page |
| theme | not configured | *not a finding* — most deployments never theme anything |

The theme checks exist because a refused override's symptom is a page that looks
*normal*. The server does not stop for one — it serves the built-in and logs —
so without this the only evidence scrolled past at startup, and an operator
staring at a stock sign-in form cannot tell "refused" from "wrong directory"
from "I edited the wrong file". `signari theme check` catches it earlier still.

The three tables that arrived in later migrations (`saml_providers`,
`identity_providers`, `access_policies`) are probed first and skipped if absent,
so the command still runs against an older schema instead of erroring — and those
checks are then *not* listed in `checked:`, which is the honest answer.

## What it does not do

It does not reach the network. It reads configuration and the database, so it is
safe to run against production and cheap enough for cron. Proving the *outside*
view — that the discovery document is reachable, that the forward-auth route is
actually protected — is `proxy check` and the conformance runbook, which need a
live endpoint and a real client.
