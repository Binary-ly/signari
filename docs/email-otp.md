# Email as a second factor

A six-digit code sent by email, offered alongside TOTP and passkeys.

```
GET|POST /account/mfa/email     enrol
POST /account/security/remove   remove (factor=email_otp)
```

`/account/security` lists every way the person signs in, and from there they
remove their own email codes, authenticator app or text-message codes: behind a
recent sign-in, audited, and told on every channel the account still has. When
it was their last second factor their recovery codes go too, since a recovery
code stands in for a second factor that no longer exists.

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

Enrolling or moving the factor also needs a sign-in from **the last ten
minutes**. The same goes for every other change to how the account signs in:
TOTP, SMS, passkeys, linked accounts and recovery codes. An older session is
sent to sign in again and brought back to the page. A cookie stolen from a
browser would otherwise be enough to point the factor at an address the thief
reads, and that would outlast the cookie.

## One live code, never a queue of them

At most one code per user. Requesting another **replaces** it. Without that,
"send another code" would leave every previously issued code valid and a patient
attacker would accumulate guesses against a widening set.

| | |
|---|---|
| lifetime | 10 minutes |
| resend interval | 60 seconds |
| attempts per code | 5 |
| wrong codes in a row, across codes | 100, then the factor is switched off |
| stored as | SHA-256, compared in constant time |

A correct code is destroyed on use, whether or not the rest of the sign-in
succeeds. A one-time code that survives its use is not one-time.

**A hundred wrong codes in a row switch the factor off**, the same ceiling an
authenticator app has. The holder is told, and no more codes are sent or
accepted until an address is proved again. The account still asks for a second
factor, and the way in is a recovery code or another method. Five guesses per
code, with a new code every minute and nothing counting across codes, came to
about 960 guesses a day at a six-digit code, indefinitely. A right code resets
the count.

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

## Signing in with an emailed code alone

A code to the account's address can also be the whole sign-in, with no
password. It is off unless the organisation's sign-in flow takes it, with an
`email_otp` stage on `proved_by_email` ([sign-in flows](flows.md#signing-in-with-an-emailed-code)).
The sign-in page then offers **Email me a code instead** under the password.

```
POST /login/email          what was typed in the name box; answers with the code page
POST /login/email/verify   the code; answers with the sign-in
```

The code page says the same thing whether or not an account has that name, and
the request does the same work either way. The code is queued in the outbox
when it is asked for and made when the outbox sends it, so no mail is sent while
the page waits for its answer. It is not the second factor's code: it has its own
table, its own mail, and its own token between the two pages. It never gets the
pending sign-in token, because the second-factor page accepts that token as a
proved first factor.

| | |
|---|---|
| lifetime | 10 minutes |
| codes asked for, per account | one a minute and five an hour; past that, the code already sent stays the one that works |
| codes asked for, per address | twenty an hour |
| attempts per code | 5, and each wrong one is also charged to the account's second-factor budget |
| stored as | SHA-256, compared in constant time, deleted when used |

The session records amr `otp` and acr `1`: one factor, possession of the
mailbox. `proved_by_password` is false for it, so
`{stage: mfa, when: proved_by_password}` does not ask; `when: proved_by_email`
or `when: user_has_second_factor` does. **The mailbox is one factor however many
codes go to it.** After an emailed sign-in code, email as a second factor is not
counted for `user_has_second_factor`, not sent, and not accepted on the code
page, so someone whose only second factor is email gets a one-factor session
rather than a second code to the same inbox. An authenticator app, a text
message, a security key or Duo still count. The sessions page shows such a
sign-in as "Signed in with a code sent by email". The built-in unenrolment flow
accepts it, so someone who signs in no other way can still delete their own
account.

It is worth exactly what the mailbox is worth, as with the second factor. Offer
it where the people signing in would otherwise reuse a weak password, and not as
a step up from one.

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
