# Email as a second factor

A six-digit code sent by email, offered alongside TOTP and passkeys.

```
GET|POST /account/mfa/email     enrol
```

## What it is honestly worth

**Weaker than TOTP, much weaker than a passkey**, and the enrolment screen says
so rather than presenting three factors as equivalent in a dropdown:

> This is the weakest of the second factors we offer, because account recovery
> already goes to your email — anybody with your mailbox can do both.

The reason is channel overlap. Account recovery here goes to email, so an
attacker with the mailbox can reset the password anyway. Email as a second factor
therefore adds little against a compromised mailbox and a great deal against a
**leaked password alone** — which is the common case, and why it is offered at
all. It needs no app and no phone, and the alternative many deployments choose is
no second factor whatsoever.

## Enrolment proves the address

Turning it on requires entering a code sent to the address — the same standard
the factor will be held to later. Trusting the address already on the account
would let somebody who has stolen a session enrol a factor **they** control,
which locks the real owner out rather than protecting them.

The address is stored on the credential, captured at enrolment, and **not read
live from `core.users`**. If it were read live, anyone able to change the account
email could redirect the second factor to themselves. Changing it re-enrols and
kills any code in flight.

## One live code, never a queue of them

At most one code per user. Requesting another **replaces** it. Without that,
"send another code" would leave every previously issued code valid and a patient
attacker would accumulate guesses against a widening set.

| | |
|---|---|
| lifetime | 10 minutes |
| resend interval | 60 seconds |
| attempts per code | 5 |
| stored as | SHA-256, compared in constant time |

A correct code is destroyed on use, whether or not the rest of the sign-in
succeeds. A one-time code that survives its use is not one-time.

The database enforces that a pending code always has an expiry
(`email_otp_code_has_expiry`), so a row cannot carry a code that never dies.

## The gate that had to change

The sign-in path asked `HasConfirmedTOTP` — a function whose own comment said it
reported "a usable second factor" while it only ever checked TOTP. Harmless until
email codes existed, and then immediately not: a user whose only factor was email
would have been **waved through on a password alone**, having explicitly turned on
a second factor.

It is now `HasSecondFactor`, and the query matches the name.

## Codes are best effort, sign-in is not

If SMTP is down the code is logged and the challenge page renders identically.
A user with both an app and email can still use the app, and a mail outage should
not become an authentication outage.

The failure is never surfaced *at sign-in*: telling the form that mail failed
would confirm the account exists and has email enrolled. At **enrolment** it is
said plainly, because that person is already authenticated so there is nothing to
disclose, and silently showing a code entry form for mail that never left is
cruel.

`signari doctor` reports the combination that actually locks people out:

```
[CRITICAL] mail   1 user(s) use email as a second factor and no SMTP is configured
             -> they cannot sign in: the code is written to the log instead of
                sent. Set SIGNARI_SMTP_HOST and SIGNARI_MAIL_FROM
```

## Verified end to end

Against the running server:

| | |
|---|---|
| enrol, wrong confirmation code | refused |
| enrol, correct code | enrolled, code consumed |
| sign in | challenged, code sent |
| submit the emailed code | session created |
| five wrong codes | `attempts` 1, 2, 3, 4, 5 |
| the **correct** code after those five | refused — the budget is gone until a new code is requested |

Codes are generated with `rand.Int` over the full range rather than modulo over a
random byte: a six-digit code has only a million values, so the distribution *is*
the entropy. A test asserts leading zeros survive — otherwise one user in ten
would be handed a five-digit code.
