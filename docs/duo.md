# Duo Universal Prompt

## Introduction

Duo is a service for multi-factor authentication (MFA). Some organisations
already use it, and want their people to keep using it when they sign in through
Signari.

Signari can send a person to Duo's Universal Prompt after their password, and
take Duo's answer as a second factor. It takes that answer only when Duo vouches
for the same person who is signing in.

You set it up for each organisation with `signari duo set`. You then give each
person their Duo username with `signari duo enroll`.

## Setting it up

Give Signari the organisation's Duo keys, then give a person the username Duo
knows them by:

```sh
signari duo set -org <uuid> \
  -duo-client-id DIXXXXXXXXXXXXXXXXXX \
  -duo-secret <40 characters> \
  -duo-api-host api-XXXXXXXX.duosecurity.com

signari duo enroll -email alice@corp.example -duo-username alice
```

Register `<issuer>/login/duo/callback` in Duo's administration panel, exactly as
written.

## The bug this integration exists to not have

Duo returns an ID token whose `preferred_username` is **who Duo actually
challenged**. Suppose an integration checks the signature, the issuer, the
audience and the expiry, then treats the response as "MFA passed". It will
accept a successful Duo authentication of *somebody else* as proof for the
account being signed into.

It is one line, and it is the line every rushed integration omits. This was
verified against a Duo stand-in, configured to answer about a different person:

```
callback status: 400
sessions before=5 after=5

reason: Duo authenticated "someone-else", but the account being signed into is
        "probe2". A second factor proved for one person is not a second factor
        for another.
```

This is why `signari duo enroll` demands `-duo-username` separately. Duo
identifies people by *its* username, which is frequently not their email
address. Without the mapping stored, there is nothing to compare Duo's answer
against.

## The username cannot be edited in the browser

The username travels inside the signed `request`, a
[JSON Web Token (JWT)](glossary.md#jwt), not as a query parameter:

```
GET /oauth/v1/authorize?client_id=…&request=<HS512 JWT>
```

The test asserts that `duo_uname` is absent from the query string, and present
inside the signature.

## The health check goes before the redirect

Never after. Once the browser has left, a Duo outage leaves the person on a page
that will not load. It also leaves the engine unable to apply its own fail-open
decision, because there is nothing left to decide.

`signari duo set` runs the same check before storing anything. So a wrong secret
key is a message now, not a failed sign-in later:

```
checking these keys against Duo... failed
signari: Duo refused the health check: invalid_client: Failed to verify
signature. (code 40103)

  Nothing has been stored.
```

## Fail closed by default, and fail-open means what it says

To "fail closed" is to refuse the sign-in when Duo cannot be reached. To "fail
open" is to let the sign-in continue. This is what happens when Duo is
unreachable:

| Duo is unreachable | what happens |
|---|---|
| `fail_open = false` (default) | the sign-in is **refused**, with an honest message |
| `fail_open = true`, another factor enrolled | that factor is asked for instead |
| `fail_open = true`, nothing else | signed in with **`amr: [pwd]`** and `acr: 1` |

The third row is the one that took two attempts. The first version returned
"not handled", and let the caller render a code prompt. A person whose only
factor is Duo cannot answer that. So it was fail-*closed* with a confusing page,
in a setting named fail-open. Only running it showed the difference: the status
code was 200, and nothing looked wrong.

The second attempt failed in a different way. The fail-open path finished the
sign-in by itself: it opened a transaction and handed over to the sign-in flow.
That flow's `mfa` stage saw a password-only sign-in, and started the challenge
again. So Duo was asked again, failed open again, and another transaction was
opened while the last one was still held.

Each level kept its database connection. Once the pool was empty, every sign-in
in the deployment was waiting on the Duo outage. That is the one moment
fail-open exists for.

Now the challenge only *reports* that Duo failed open. The `mfa` stage records
it in the sign-in's own transaction, and moves on. So Duo is asked once, one
transaction is held, and one session is issued
(`TestDuoFailingOpenSignsInOnceThroughThePasswordForm`, `…FromInsideTheFlow`).

Note what the third row does **not** do: claim a second factor. `amr` carries
only what was proven, so `acr` stays single-factor, and every policy asking for
MFA still refuses. Fail-open decides whether the sign-in continues. It does not
get to invent a factor.

Both are audited, with their own event types:

```
mfa.duo_unavailable         {"fail_open": true}
mfa.skipped_duo_unavailable
```

So "how often did we sign people in without a second factor?" is a question the
audit trail can answer.

The default is fail closed, and that costs something real: a Duo outage stops
every enrolled person signing in. The other side is worse, in a way that is
hard to see. An attacker who can stop one victim's traffic reaching Duo has
removed their second factor, and blocking one host is not a high bar.

## Everything else that is checked

Signari also checks each of these in Duo's answer:

| | |
|---|---|
| algorithm | fixed at HS512, never read from the header — `alg: none` is refused |
| issuer | `https://<api-host>/oauth/v1/token`; another Duo tenant is not ours |
| audience | this integration's client id |
| expiry | required — a token with no `exp` would be a permanent second factor |
| `auth_result.status` | a `deny` from Duo is a refusal, not a successful exchange |
| state | 22–1024 characters, inside the signed request, **single-use** |
| API host | must be `duosecurity.com` or `duofederal.com`, in code *and* in a database constraint |

The host constraint is not fussiness. Every call carries a signed assertion
naming this integration. A host somewhere else hands that assertion to whoever
runs it.

## No JWT library

Signari checks Duo's tokens with thirty lines of `crypto/hmac`. A JWT library in
the authentication path is a supply chain in the authentication path, and this
one only ever needs HS512.

## Verified

This was verified against a Duo stand-in that speaks the real protocol. The
stand-in was built with Python's `hmac`/`hashlib`, not with this engine's code,
so an accepted token is two implementations agreeing:

| | |
|---|---|
| password → Duo | 303 to the prompt, challenge recorded, **no session yet** |
| callback | `acr: 2`, `amr: [pwd, mfa]`, `mfa.duo_succeeded` audited |
| Duo answers about another user | 400, no session |
| Duo is down, fail closed | 400, honest message |
| Duo is down, fail open, no other factor | signed in, `amr: [pwd]` only |
| keys checked at `duo set` | wrong secret refused before anything is stored |

One accident is worth recording. An early run reached **real Duo**, because
`api-1234abcd.duosecurity.com` resolves. It answered `invalid_client`,
correctly, which is a better test of the health-check path than the stand-in
gave.

### The stand-in is not a production affordance

`SIGNARI_DUO_BASE_URL` is refused unless `SIGNARI_INSECURE_ISSUER=1` is already
set. That is, unless the deployment has already declared itself not production:

```
signari: a Duo base URL override is only available on a deployment that has
already allowed an insecure issuer; on a real deployment it would be a way to
point the second factor at another server
```

The first version of that gate read an environment variable that does not exist
(`SIGNARI_ALLOW_INSECURE_ISSUER`). So the override never applied, and the engine
logged an error the sign-in page never showed. That is exactly what the
documented-but-absent sweep in [security scanning](security-scanning.md) looks
for, and it is now clean.

## Duo counts as a second factor — and the gate now proves it

Adding Duo took the bug the MFA gate has now had three chances at. The
enrolment table was written and the challenge was wired up, but
`HasSecondFactor` was not updated. So a person whose only factor was Duo would
have signed in on a password alone.

Worse, the test meant to catch that **passed**. It discovered factor tables by
matching `%otp_credentials`, and Duo's table is `duo_enrollments`. A test that
fails to look is not a weak test: it is a no-test that reports success.

It now classifies every credential table explicitly, and fails when a new one
appears that nobody has classified. That at once caught two more
(`password_credentials`, `recovery_requests`) that needed a decision recorded.
