# Sign-in flows

A flow is the sequence of things somebody is asked for on the way in: a
challenge, a password, a second factor, a notice they have to accept. Signari
takes it as a file.

```yaml
version: 1
flows:
  - name: sign-in
    on: authentication
    stages:
      - {stage: captcha, when: captcha_required}
      - one_of:
          - {stage: passkey, when: user_has_passkey}
          - {stage: password}
      - {stage: mfa, when: user_has_second_factor}
      - session
    tests:
      - name: passkey holder
        given: {user_has_passkey: true}
        expect: [passkey, session]
      - name: password and a second factor
        given: {user_has_second_factor: true}
        expect: [password, mfa, session]
```

```
signari flow test  -flow-file flows.yaml              # in CI: no database needed
signari flow paths -flow-file flows.yaml              # every journey it admits
signari flow apply -org <uuid> -flow-file flows.yaml  # install it
signari flow show                                     # the built-in flows
```

The Admin API reads and applies the same file at
`/admin/organizations/{orgID}/sign-in-flow`, parsed and tested the same way
before it is stored; see [admin-api.md](admin-api.md).

## What is different here


**A flow that could issue a session without proving who the subject is does not
load.**

That is checked when the file is parsed — by `signari flow test` in CI, and again
by the engine before it serves anything. It is not a warning and cannot be
waived.

### The flow this exists to refuse

```yaml
stages:
  - identify
  - session
```

Two steps. It asks for a username, finds the account, and signs them in. Nothing
was proved: knowing a username is not evidence of owning it.


Both ask the right question. Both ask it of a configuration that has already been
saved, published and served, with somebody waiting on the answer.

### The subtler one

```yaml
stages:
  - identify
  - enrol_mfa
  - mfa
  - session
```

Read quickly it enrols a factor and then demands it — two factors' worth of
words. What it does is let a stranger name an account, attach their own
authenticator to it, present that authenticator, and be signed in as its owner.
The `mfa` stage passes honestly. It is proof of possession of a secret created
two steps earlier by the person being asked.

So there is a second rule: **a stage that changes a credential may not run before
one that checks a credential.** Same for `password_change`, which is the older
and more obvious version of the same bug.

## The file

### Designations

| `on:` | what it is | rules | endpoint |
|---|---|---|---|
| `authentication` | signing in | must prove the subject before a session | `/login` |
| `enrolment` | creating an account | exempt from proof — and may not reach a session | `/signup` |
| `recovery` | restoring lost access | must prove the subject, from a **narrower** set of factors | `/recover`, `/recover/reset` |
| `unenrolment` | deleting one's own account | must prove the subject before `done` | `/account/delete` |

**All four run.** `unenrolment` is the person deleting their own account from
`/account/delete`. The page needs a recent sign-in, refuses an impersonation
session, and has the person type their address or username to confirm; the
proving stage is that sign-in, each proof counting only for itself as at sign-in,
and `done` erases the account exactly as `signari erase subject` does — the key
their data is sealed under destroyed, every session ended with each application
sent a back-channel logout, the account deleted, audited `account.deleted` — and
the address is sent one last message. An unenrolment's `done` is held to the
proof rule a `session` is held to, so `[done]` is refused. The built-in flow
accepts every way in; `stages: [deny]` closes self-service deletion, and
`stages: [passkey, done]` lets only a passkey sign-in delete. Until October 2026
nothing walked this designation, and deletion was an operator's act only.

### What a recovery flow governs, and what it refuses

Recovery is two requests separated by an email, so the flow is consulted twice:
`captcha` and `identify` at `/recover`, then `email_otp`, `mfa`, `password_change`
and the terminal at `/recover/reset`.

`mfa` before `password_change` asks whoever holds the link for a second factor
before the new-password form appears: an authenticator app's code, a recovery
code, or a code texted to the account's phone. Never an emailed code, which goes
to the mailbox the link already proved. Somebody with none is told to ask an
administrator, and nothing is changed. The terminal may be `session`, which ends
the reset signed in through the organisation's ordinary sign-in from there; a
sign-in flow that wants more than the new password and any factor proven on the
way asks for it.

A second factor proven on the link's page also **waives the reset delay**, with
or without an `mfa` stage. The delay is the window in which somebody who took
over the mailbox can be stopped by the owner cancelling, and a second factor is
what that somebody does not have. While the delay runs, the page offers the
factor in place of waiting, and the reset is recorded as waived by it
(`account.recovery_factor_proven`, then `account.password_reset` with
`waived_by`). Until October 2026 the waiver existed and nothing called it.

A stage the engine cannot execute in a recovery journey — `sms_otp` as the
proving channel, `passkey` recovery — **refuses the file** when
it is parsed, like any stage a journey does not run (see [Stages](#stages)).
Skipping it would reset the password having proved less than the file requires,
which is the failure the flow engine exists to prevent. A flow that reaches the
journey some other way still stops it with a 501 before anything is written, so
the credential is left untouched.

The `captcha` stage at `/recover` reads the **default** organisation's flow, not
the account's. That is deliberate: `/recover` answers identically whether or not
an account exists, and a journey that varied by account would be an enumeration
oracle wearing a configuration setting.

Requests at `/recover` are paced whatever the flow says. An account gets at most
one reset link a minute and five an hour, and one address may make twenty
requests an hour. A request over the pace writes nothing and sends nothing. In
particular it does not supersede the link the person already has, so an
attacker cannot keep a victim's link from ever working by asking again every
few seconds. It answers with the same page as any other request, so the pace
gives nothing away.

Recovery counts fewer factors on purpose. A flow that resets a password by asking
for the password is not a recovery flow, and one that asks for the second factor
from the phone that was lost is a support ticket. What counts: `email_otp`,
`sms_otp`, `passkey`, `certificate`, `kerberos`, `federated`, of which a recovery
journey runs `email_otp` today.

Enrolment is exempt from the proof rule because there is nobody yet to prove. It
pays for that by not being allowed to issue a session: sign-up decides who
exists, and an authentication flow decides who is signed in. Collapsing the two
is how a self-service form becomes an account-creation-and-login endpoint.

### Stages

Proving — establish the subject:

`password`, `passkey`, `mfa`, `email_otp`, `sms_otp`, `certificate`, `kerberos`,
`federated`, `delegated`

Not proving:

`identify`, `captcha`, `consent`, `prompt`, `password_change`, `enrol_mfa`,
`verify_email`, `create_user`, `invitation`

Terminal — a flow ends in exactly one, and it must be last:

`session` (issues one), `done` (finished, no session), `redirect` (finished, no
session, and the browser sent to the step's `to`), `deny` (refused)

`identify` sitting in the second list is the whole design. `password_change` is
there too, and for a reason worth stating: it takes a password, but it *sets* a
credential rather than checking one.

**A flow may name only the stages its journey runs.** A sign-in used to walk
past every stage it did not act on, so `password, kerberos, session` read as two
proofs and was a password sign-in. A sign-up or recovery stopped at such a
stage with a 501 the first time somebody tried it. Either way the operator was
the last to find out, so the file is refused when it is parsed, naming the
stage.

| `on:` | stages it runs |
|---|---|
| `authentication` | `mfa`, `enrol_mfa`, `verify_email`, `prompt`, `password_change` and the terminals, which the sign-in acts on; `identify`, `captcha`, `password`, `passkey`, `kerberos`, `federated`, `email_otp` and `consent`, which the route that reached the walk settles before it: the sign-in form, the passkey ceremony, the Negotiate exchange, a provider's callback, the emailed code's page, the authorization endpoint |
| `enrolment` | `captcha`, `prompt`, `invitation`, `create_user`, `deny`, `done`, `redirect` |
| `recovery` | `captcha`, `identify`, `email_otp`, `mfa`, `password_change`, `deny`, `done`, `session`, `redirect` |
| `unenrolment` | `password`, `passkey`, `kerberos`, `federated`, `email_otp`, settled by the recent sign-in that reached `/account/delete`, each only by its own proof; `deny`; `done`, where the account is erased |

The rest wait for a driver: `delegated` and `certificate` (a source the flow
would have to pin), and `sms_otp` as a first factor at sign-in.
The safety rules still know them, so a file naming one is refused for the right
reason rather than read as a typo.

### Sign-up by invitation, and ending somewhere else

`invitation` lets a sign-up through only with an invitation that is still good,
whatever self-signup rule the organisation has. The `invited` condition says
whether this one carries one, so invited people can be asked less:

```yaml
on: enrolment
stages:
  - invitation          # sign-up by invitation alone
  - create_user
  - {stage: redirect, to: "https://intranet.example.com/welcome"}
```

```yaml
  - {stage: captcha, when: not invited}
```

`redirect` ends an enrolment or a recovery by sending the browser to `to`
instead of the built-in page: after a sign-up, to an onboarding page; after a
reset, back to the application. `to` is checked when the file is read. It must
be an `https` URL with no user information, or a path on this server starting
with a single slash. Another scheme, `//elsewhere`, and `to` on any stage but a
redirect are refused by name. A sign-up an application asked for with
`prompt=create` still ends on the page that leads back to that application,
which is owed its answer. A sign-in may not end in a redirect, since its end is
the session the parked request resumes from. Nor may an unenrolment, whose
`done` is where the account is erased; that `done` is also the stage that
deletes a user, so the language has no second one.

### Requiring somebody to enrol a second factor

`enrol_mfa` holds the sign-in of somebody with no second factor until they
enrol an authenticator app: the enrolment page, then their recovery codes, then
the sign-in goes on through the rest of the flow. Somebody with a factor passes
it. Written with the challenge, it is "ask for the factor, or make them enrol
one":

```yaml
- password
- {stage: mfa, when: user_has_second_factor}
- {stage: enrol_mfa, when: not user_has_second_factor}
- session
```

Enrolling proves nothing about who is signing in, since anyone with the
password could have done it, so it adds nothing to the session: under this
flow the new authenticator is asked for its next code at once, and the session
is multi-factor; under `password, enrol_mfa, session` it is password-only. The
enrolment pages answer only a sign-in this stage held, and never for somebody
who has a factor, so a password cannot be used through them to replace an
existing authenticator. Only an authenticator app can be enrolled here; a
passkey is added from the account page. Until October 2026 a flow naming
`enrol_mfa` was refused when parsed, and an unconditional `mfa` turned away
everybody with nothing enrolled.

### Confirming a self-sign-up's address

`verify_email` holds a sign-in until a code sent to the account's address comes
back, for an account self-sign-up made under a rule that requires a proved
address (`signari signup enable`, on by default). The built-in flow runs it
straight after the proof:

```yaml
- {stage: verify_email, when: email_verification_pending}
```

The right code sets the address verified, so ID tokens and `/userinfo` say
`email_verified: true`, and the sign-in goes on from the start. Accounts an
administrator made, or self-sign-ups under a rule with `-verify-email=false`,
have nothing outstanding and pass. A wrong code counts against the same
per-account budget as a second factor, and twenty across codes close the
confirmation; resetting the password from the emailed link then proves the
address instead, as any completed reset does. Until October 2026 the rule's
setting was consulted by nothing, so a rule naming one domain let anybody sign
up, and straight in, as any address there.

### A sign-in's proving stage is the proof presented

Somebody reaches a sign-in by exactly one of five routes, and the flow's
proving stage must be that route's proof: `password` for the sign-in form
(including a password checked against the provider being migrated off),
`passkey` for the passkey ceremony, `kerberos` for a Negotiate ticket,
`federated` for an upstream provider, `email_otp` for a code emailed to the
account's address. A sign-in by any other proof is refused,
and the refusal is audited as `login.failed` with the reason
`flow_requires_another_proof`, the stage required and the one presented.

```yaml
# Passkeys only: a password, a ticket or a provider is refused.
stages: [passkey, session]

# Everybody who arrives today, each by name; the built-in flow is this.
stages:
  - one_of:
      - {stage: passkey,   when: proved_by_passkey}
      - {stage: kerberos,  when: proved_by_kerberos}
      - {stage: federated, when: proved_by_federated}
      - {stage: password}
  - session

# A second factor only for people who came in with a password.
  - {stage: mfa, when: proved_by_password}
```

The `proved_by_password`, `proved_by_passkey`, `proved_by_kerberos`,
`proved_by_federated` and `proved_by_email` conditions say which route was
taken. A journey asking for two of these proofs could only refuse whoever walks
it, since nobody arrives by two routes, so it is refused when the file is
parsed, naming both:
`password, kerberos, session` is refused, and a second check belongs in `mfa`.
In the example at the top of this page, a passkey holder must use their passkey,
and Kerberos and provider sign-ins are refused, because neither is offered.

**Until October 2026 the walker passed `password` and `passkey` whatever had
been presented.** `passkey, session` admitted a password, and the `one_of` at
the top of this page let a passkey holder in on a password. A flow written
before then that names only `password` now refuses passkey, Kerberos and
provider sign-ins; add them as `one_of` alternatives to keep admitting them.
`signari flow paths` shows every journey a file admits.

### Signing in with an emailed code

No built-in flow takes a code to the mailbox as the whole sign-in, because it
is worth no more than the mailbox. A flow that names it turns it on, and the
sign-in page then offers **Email me a code instead**:

```yaml
stages:
  - one_of:
      - {stage: email_otp, when: proved_by_email}
      - {stage: password}
  # Ask an emailed sign-in for an authenticator, when the person has one.
  - {stage: mfa, when: user_has_second_factor}
  - session
```

The session records amr `otp`, one factor. After an emailed code,
`user_has_second_factor` does not count email as a second factor, and the code
page neither sends nor accepts an email code, because the same mailbox twice is
still one factor. [Email codes](email-otp.md#signing-in-with-an-emailed-code-alone)
covers the pages, the pacing and what is withheld from somebody guessing names.
Until October 2026 a flow naming `email_otp` at sign-in was refused when it was
parsed.

### Conditions

A `when:` is one condition, optionally negated with `not`. There is no `and` or
`or` — a flow needing two facts writes two steps.

`user_has_second_factor`, `user_has_passkey`, `user_is_new`,
`password_change_required`, `prompts_pending`, `consent_required`,
`captcha_required`, `risk_elevated`, `device_managed`, `device_compliant`,
`network_trusted`, `client_requires_mfa`, `kerberos_available`,
`migration_pending`, `federated_source`, `email_verification_pending`,
`proved_by_password`, `proved_by_passkey`, `proved_by_kerberos`,
`proved_by_federated`, `proved_by_email`, `invited`

The list is closed, and a condition outside it is refused at parse. That is what
makes a typo an error rather than a stage that silently never runs. It is also
what makes the analysis possible: these are the only things a flow can branch on,
so "every path" is a set that can be walked.

**A flow may branch only on what its journey evaluates.** A condition the
engine cannot answer would read false every time, so a step-up written as
`{stage: mfa, when: device_managed}` would pass its own tests (which set the
condition true) and never ask anybody for anything. Such a flow is refused when
it is parsed, naming the condition: by `signari flow test`, by `signari flow
apply` and by the engine's load alike.

| `on:` | conditions it evaluates |
|---|---|
| `authentication` | `user_has_second_factor`, `user_has_passkey`, `password_change_required`, `prompts_pending`, `client_requires_mfa`, `risk_elevated`, `email_verification_pending`, and the five `proved_by_*`; `captcha_required` only as the condition of the `captcha` stage, because a sign-in settles the challenge at the form before the flow is walked |
| `enrolment` | `captcha_required`, `invited` (the sign-up carries an invitation that is still good), `prompts_pending` (always false: there is no account yet to have one) |
| `recovery` | `captcha_required` |
| `unenrolment` | the five `proved_by_*`: which way the person signed in to reach the page |

The rest of the list (`user_is_new`, `consent_required`,
`device_managed`, `device_compliant`, `network_trusted`, `kerberos_available`,
`migration_pending`, `federated_source`) is part of the language, so a file
naming one is understood rather than mistaken for a typo, and no journey
evaluates it yet.

`risk_elevated` holds when the sign-in could not have followed the person's
last one (impossible travel), or comes from a country they have never signed in
from. Both need a GeoIP source, `SIGNARI_GEOIP_DB` or `SIGNARI_GEOIP_STATIC`
(see [configuration](configuration.md)), and history: with neither, nothing
fires, so a first sign-in, or a deployment with no database, is never stopped
for want of a signal. `{stage: mfa, when: risk_elevated}` asks for the second
factor only then. Until October 2026 a sign-in read it false.

A flow stored before this rule existed, or written to the table directly, no
longer loads. That organisation is served the last flow that loaded, or the
built-in one after a restart. The engine logs the refusal once per document,
and `signari doctor` reports it as critical, naming the organisation.

### `one_of`

```yaml
- one_of:
    - {stage: passkey, when: user_has_passkey}
    - {stage: password}
```

Exactly one branch runs: the first whose condition holds, and the last branch has
no condition, so there is always one. **The last branch must be the default** —
that is what makes the group total.

Written instead as two conditional stages:

```yaml
- {stage: passkey,  when: user_has_passkey}
- {stage: password, when: not user_has_passkey}
```

…the file is refused. A person reads those two conditions as exhaustive; the
analysis cannot, so it must consider the path where both are false, and that path
reaches a session having proved nothing. `one_of` is the author making the same
claim in a form that can be *checked* rather than believed.

This is the one place the analysis refuses something safe. It is sound — it never
admits an unsafe flow — and deliberately incomplete, because the cost of a false
refusal is an error message and the cost of a false acceptance is a stranger
holding a session.

### Tests are required

A flow file with no `tests:` does not load, and the cases run every time the file
is parsed — not only under `flow test`. A flow whose stated intent disagrees with
its behaviour is refused rather than deployed. Same rule as
[policy files](policy.md).

`expect:` is the exact ordered sequence, not a set. A flow that runs an extra
stage nobody expected is as wrong as one that skips a required stage, and the
second kind is the kind that gets somebody in.

## `flow paths`

```
$ signari flow paths

  the built-in flows (no -flow-file given)

  default-sign-in (authentication)
    password -> session                                         nothing in particular
    captcha -> password -> session                              captcha_required
    passkey -> session                                          proved_by_passkey
    captcha -> passkey -> session                               captcha_required, proved_by_passkey
    kerberos -> session                                         proved_by_kerberos
    federated -> session                                        proved_by_federated
    password -> mfa -> session                                  user_has_second_factor
    ...
```

Every journey the file admits, and the situation that produces each. A flow file
is read one step at a time and lived one journey at a time; the gap between those
two readings is where a misconfiguration hides, and enumerating removes it.


## Defaults

A deployment that has written no flow file runs the built-in ones, which
reproduce exactly the journey the server ran when the sequence was fixed Go:

```
captcha (if required) -> password, passkey, kerberos or federated (whichever was presented)
  -> verify_email (if a self-sign-up's address is unproved) -> mfa (if enrolled)
  -> prompt (if pending) -> password_change (if flagged) -> session
```

`signari flow show` prints that file verbatim, to start from. It is parsed by the
same `Parse`, so the safety analysis and its own test cases run against it in CI:
the default journey is held to exactly the rules an operator's file is held to,
rather than being trusted because it shipped.

## What the flow controls today

Applied with `flow apply`, the file drives the live sign-in:

- **whether a second factor is demanded** — `when: user_has_second_factor`
  reproduces the old behaviour; unconditional demands one of everybody; `when:
  client_requires_mfa` demands one only when a relying party sends
  `acr_values=2`, or the client requires it (below)
- **which of the post-authentication stages run, and in what order** — the
  prompt and the forced password change
- **refusing outright**, with `deny`

It does **not** control the password check, the credential lookup, the login
throttle, or the rate limiter. Those are not sequencing decisions, and putting
them in a file would mean an operator could turn them off.

The `mfa` stage binds every way in: password, passkey, Kerberos, Duo and the
federated sources all reach a session through the same walk. A sign-in whose
factors already add up to multi-factor passes the stage without being asked
again. Otherwise the person is asked for a factor enrolled here, and under an
unconditional stage somebody with none is refused. A federated sign-in counts
as multi-factor only when the provider's ID token asserts it with a value you
chose to trust; see [social-login.md](social-login.md#a-providers-multi-factor-authentication).

A registered security key or passkey is one of those factors: after a password,
the code page offers a button that asks for it, and password plus key gives a
multi-factor session. Until October 2026 it was not. A person whose one factor
beyond the password was a key signed in on the password alone, and a relying
party sending `acr_values=2` was told the account had no second factor. Anybody
who has registered a passkey and signs in with a password is now asked for the
key as well; signing in with the passkey itself is unchanged.

### Remembering a device

`signari instance remember-device -org <id> -days 30` puts a "remember this
device" box on the code page. A browser that ticked it, after a second factor,
passes the `mfa` stage on later sign-ins for that many days, unless the
application requires multi-factor, by asking with `acr_values=2` or through a
floor (below). Such a session records what was proved, the password, so it is
single-factor, and a requirement for more is met by asking for the factor
again. The browser holds a random token and the database its hash, checked at
every sign-in, so a device stops counting at the next one when the person
forgets it at `/account/devices`, when they sign out everywhere, or when the
organisation sets `-days 0`. Off unless set.

### Requiring multi-factor for one application

`signari client set-acr -client-id payroll -minimum-acr 2` requires
multi-factor of that client whatever its request says. A relying party can ask
with `acr_values=2`; this is for the one that does not, and for a request a
user can edit, since the parameter can be removed from the URL. The floor is
checked wherever a person's session here gives the client tokens:

- **authorization.** A session with a single factor is not reused: the person
  is asked for a second, and someone with none enrolled is refused with
  `unmet_authentication_requirements` rather than shown the sign-in form again.
  So is someone with a factor whose flow never asks a password sign-in for one
  and who has no passkey, for `acr_values=2` as well: the form could only give
  them one factor, and brought them back to it. Until October 2026 that looped.
  `client_requires_mfa` holds for the client's sign-ins, so a flow that demands
  a factor only on request demands it here
- **a device or backchannel approval** from a single-factor session is refused,
  saying to sign in again with a second factor
- **every refresh.** A refresh token from a single-factor session is refused
  with `invalid_grant`, so raising the floor reaches the tokens already issued

Token exchange and the JWT bearer grant are not held to it, because neither
starts from a session here: one carries a token already issued, the other an
assertion from an issuer you trust. Until October 2026 nothing set a floor for
a client.

### Above multi-factor: a passkey or security key

Two rungs go above `2`, as a floor (`-minimum-acr 3` or `4`) or in a request's
`acr_values`:

| | |
|---|---|
| `3` | multi-factor that includes a WebAuthn assertion: a passkey that verified its user, or a security key after a password. The assertion is bound to this server's origin, so a page that relays the sign-in cannot obtain one. An authenticator app, a text or a federated sign-in does not reach it |
| `4` | the same with a key bound to its device. A synced passkey can be copied to another device, so it does not reach `4` |

These are this engine's rungs, not values another server will recognise. A
session still records `1` or `2`, so an ID token says what it said before. A
request that asked for `3` or `4` and got it is told that value instead. An
account with no key that reaches the rung is refused with
`unmet_authentication_requirements`. With one, the sign-in form says which
sign-in the application wants. The floor reaches approvals and refreshes as `2`
does.

An organisation with no flow applied runs the built-in file, so nothing changes
until somebody applies one.

## Not a graph

Flows are a list, `when` is one condition, and the only branching construct
states its own exhaustiveness. Those three restrictions are why the safety
question is decidable at all — with arbitrary expressions and a general graph it
becomes satisfiability, and the honest options at that point are to solve it or
to stop claiming the guarantee.


## See also

