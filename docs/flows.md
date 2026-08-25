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
| `unenrolment` | deleting an account | must prove the subject | **none — see below** |

**Three of the four run.** `unenrolment` is defined, parsed and safety-checked,
and nothing executes it, because there is no self-service unenrolment journey in
this engine to execute: deleting an account is `signari erase subject` and the
admin API, which are operator actions rather than a sequence a subject walks. The
designation exists so that a file declaring one is understood rather than
rejected, and so the language does not have to change on the day such an endpoint
is built. `signari flow test` says so about any flow it cannot run, and
`signari flow apply` warns before storing one.

### What a recovery flow governs, and what it refuses

Recovery is two requests separated by an email, so the flow is consulted twice:
`captcha` and `identify` at `/recover`, then `email_otp`, `password_change` and
the terminal at `/recover/reset`.

A stage the engine cannot execute in a recovery journey — `mfa` before a reset,
`sms_otp` as the proving channel, `passkey` recovery — **stops the journey** with
a 501 rather than being skipped. Skipping it would reset the password having
proved less than the file requires, which is the failure the flow engine exists
to prevent. The refusal happens before anything is written, so a flow this engine
cannot honour leaves the credential untouched.

The `captcha` stage at `/recover` reads the **default** organisation's flow, not
the account's. That is deliberate: `/recover` answers identically whether or not
an account exists, and a journey that varied by account would be an enumeration
oracle wearing a configuration setting.

Recovery counts fewer factors on purpose. A flow that resets a password by asking
for the password is not a recovery flow, and one that asks for the second factor
from the phone that was lost is a support ticket. What counts: `email_otp`,
`sms_otp`, `passkey`, `certificate`, `kerberos`, `federated`.

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
`create_user`

Terminal — a flow ends in exactly one, and it must be last:

`session` (issues one), `done` (finished, no session), `deny` (refused)

`identify` sitting in the second list is the whole design. `password_change` is
there too, and for a reason worth stating: it takes a password, but it *sets* a
credential rather than checking one.

### Conditions

A `when:` is one condition, optionally negated with `not`. There is no `and` or
`or` — a flow needing two facts writes two steps.

`user_has_second_factor`, `user_has_passkey`, `user_is_new`,
`password_change_required`, `prompts_pending`, `consent_required`,
`captcha_required`, `risk_elevated`, `device_managed`, `device_compliant`,
`network_trusted`, `client_requires_mfa`, `kerberos_available`,
`migration_pending`, `federated_source`

The list is closed, and a condition outside it is refused at parse. That is what
makes a typo an error rather than a stage that silently never runs. It is also
what makes the analysis possible: these are the only things a flow can branch on,
so "every path" is a set that can be walked.

**Not all of them are wired in yet**, and the difference matters — a condition
the engine cannot answer is false, so the stage it guards never runs, and a
control that never runs is not a control.

| condition | today |
|---|---|
| `user_has_second_factor`, `prompts_pending`, `password_change_required`, `client_requires_mfa` | **evaluated** |
| `captcha_required` | decided at the sign-in form, before the flow is walked |
| the rest | not yet evaluated — treated as false |

Applying a flow that branches on one of "the rest" logs a warning naming the
condition and the flow, once per document. It is not refused: writing a flow
against a signal before the signal is wired in is reasonable, being surprised by
it later is not.

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
    password -> session                                    nothing in particular
    captcha -> password -> session                         captcha_required
    password -> mfa -> session                             user_has_second_factor
    password -> prompt -> session                          prompts_pending
    password -> password_change -> session                 password_change_required
    ...
```

Every journey the file admits, and the situation that produces each. A flow file
is read one step at a time and lived one journey at a time; the gap between those
two readings is where a misconfiguration hides, and enumerating removes it.


## Defaults

A deployment that has written no flow file runs the built-in ones, which
reproduce exactly the journey the server ran when the sequence was fixed Go:

```
captcha (if required) -> password -> mfa (if enrolled)
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
  `acr_values=2`
- **which of the post-authentication stages run, and in what order** — the
  prompt and the forced password change
- **refusing outright**, with `deny`

It does **not** control the password check, the credential lookup, the login
throttle, or the rate limiter. Those are not sequencing decisions, and putting
them in a file would mean an operator could turn them off.

One honest limitation. `completeSignIn` has ten callers — password, passkey,
Kerberos, Duo, and the federated sources among them — and exactly one of them,
the password path, gates on a second factor today. The `mfa` stage is decided on
that path only. Routing the other nine through it would start demanding a code
from, say, a Kerberos user who happens to have TOTP enrolled: arguably an
improvement, and not one that should arrive as a side effect of moving the
sequence into a file. Whether those paths should gate on a second factor is a
separate decision.

An organisation with no flow applied runs the built-in file, so nothing changes
until somebody applies one.

## Not a graph

Flows are a list, `when` is one condition, and the only branching construct
states its own exhaustiveness. Those three restrictions are why the safety
question is decidable at all — with arbitrary expressions and a general graph it
becomes satisfiability, and the honest options at that point are to solve it or
to stop claiming the guarantee.


## See also

