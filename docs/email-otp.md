# Email as a second factor

## Introduction

A "second factor" is a second proof of who someone is, after their password.
Not everyone has an authenticator app or a phone for text messages. Almost
everyone who signs in has an email address.

Signari can send a six-digit code by email as a second factor. It is offered
alongside time-based one-time passwords (TOTP) from an authenticator app, and
passkeys. Where an organisation's sign-in flow allows it, an emailed code can
also be the whole sign-in, with no password.

People enrol and remove the factor themselves, from their account.

## Turning it on and off

A person enrols at one address, and removes the factor at another:

```
GET|POST /account/mfa/email     enrol
POST /account/security/remove   remove (factor=email_otp)
```

`/account/security` lists every way the person signs in. From there, they can
remove their own email codes, authenticator app or text-message codes. Removing
one needs a recent sign-in, and is audited. The person is told on every channel
the account still has.

When it was their last second factor, their recovery codes go too. A recovery
code stands in for a second factor that no longer exists.

## What it is honestly worth

**Weaker than TOTP, much weaker than a passkey**. The enrolment screen says so,
instead of presenting three factors as equivalent in a dropdown:

> This is the weakest of the second factors we offer, because account recovery
> already goes to your email — anybody with your mailbox can do both.

The reason is that the two channels overlap. Account recovery here goes to
email, so an attacker with the mailbox can reset the password anyway.

So email as a second factor adds little against a compromised mailbox. It adds a
great deal against a **leaked password alone**, which is the common case, and
why it is offered at all. It needs no authenticator app and no phone. The
alternative many deployments choose is no second factor whatsoever.

## Enrolment proves the address

Turning it on requires entering a code sent to the address. That is the same
standard the factor will be held to later. Trusting the address already on the
account would let somebody who has stolen a session enrol a factor **they**
control. That locks the real owner out, instead of protecting them.

The address is stored on the credential, captured at enrolment, and **not read
live from `core.users`**. If it were read live, anyone able to change the
account email could redirect the second factor to themselves. Changing the
address re-enrols, and kills any code in flight.

Enrolling or moving the factor also needs a sign-in from **the last ten
minutes**. The same goes for every other change to how the account signs in:
TOTP, text-message codes (SMS), passkeys, linked accounts and recovery codes. An
older session is sent to sign in again, and brought back to the page. Otherwise
a cookie stolen from a browser would be enough to point the factor at an address
the thief reads, and that would outlast the cookie.

## One live code, never a queue of them

Each person has at most one code. Requesting another **replaces** it. Without
that, "send another code" would leave every previously issued code valid. A
patient attacker would then collect guesses against a widening set.

These are the limits on a second-factor code:

| | |
|---|---|
| lifetime | 10 minutes |
| resend interval | 60 seconds, within one sign-in |
| codes mailed, per account | 10 an hour |
| attempts per code | 5 |
| wrong codes in a row, across codes | 100, then the factor is switched off |
| stored as | SHA-256, compared in constant time |
| taken for | the sign-in it was sent for, and no other |

A correct code is destroyed on use, whether or not the rest of the sign-in
succeeds. A one-time code that survives its use is not one-time.

**A code finishes only the sign-in it was sent for**, as the Application
Security Verification Standard (ASVS) 5.0.0 V6.6.2 asks. The sign-in's pending
token names an attempt, and the hash of that attempt is kept beside the code.
Given in any other sign-in, earlier or later, or in a browser that started
none, the code is no code at all. Nothing is counted against it.

A Lightweight Directory Access Protocol (LDAP) bind, a Remote Authentication
Dial-In User Service (RADIUS) request and the
[desktop sign-in](desktop-login.md) send no code, so they take none. Until
November 2026, a code was bound only to the person. So a code sent for a
sign-in in one browser could finish another, and a bind took a texted code sent
for a browser's sign-in.

A second sign-in therefore gets a code of its own at once, even within the
minute, and the first sign-in's code stops working. The minute applies to a
resend within one sign-in. What stops somebody with the password from filling
the inbox is the limit of ten codes an hour per account. Past that, nothing is
sent, and the page looks the same.

**A hundred wrong codes in a row switch the factor off**, the same ceiling an
authenticator app has. The holder is told. No more codes are sent or accepted
until an address is proved again. The account still asks for a second factor,
and the way in is a recovery code or another method.

Without this ceiling, five guesses per code came to about 960 guesses a day at
a six-digit code, indefinitely. That is with a new code every minute, and
nothing counting across codes. A right code resets the count.

The database enforces that a pending code always has an expiry
(`email_otp_code_has_expiry`), so a row cannot carry a code that never dies.

## The gate that had to change

The sign-in path asked `HasConfirmedTOTP`, a function whose own comment said it
reported "a usable second factor". Yet it only ever checked TOTP. That was
harmless until email codes existed, and then at once it was not. A person whose
only factor was email would have been **waved through on a password alone**,
after explicitly turning on a second factor.

It is now `HasSecondFactor`, and the query matches the name.

## Codes are best effort, sign-in is not

If mail delivery, over the Simple Mail Transfer Protocol (SMTP), is down, the
code is logged and the challenge page renders identically. A person with both an
authenticator app and email can still use the authenticator app. A mail outage
should not become an authentication outage.

The failure is never surfaced *at sign-in*. Telling the form that mail failed
would confirm that the account exists and has email enrolled.

At **enrolment** it is said plainly. That person is already authenticated, so
there is nothing to disclose. Silently showing a code entry form for mail that
never left would be cruel.

`signari doctor` reports the combination that actually locks people out:

```
[CRITICAL] mail   1 user(s) use email as a second factor and no SMTP is configured
             -> they cannot sign in: the code is written to the log instead of
                sent. Set SIGNARI_SMTP_HOST and SIGNARI_MAIL_FROM
```

## Signing in with an emailed code alone

A code to the account's address can also be the whole sign-in, with no password.
It is off unless the organisation's sign-in flow takes it, with an `email_otp`
stage on `proved_by_email`
(see [signing in with an emailed code](flows.md#signing-in-with-an-emailed-code)).
The sign-in page then offers **Email me a code instead** under the password.

The sign-in takes two requests, one for the code and one to give it back:

```
POST /login/email          what was typed in the name box; answers with the code page
POST /login/email/verify   the code; answers with the sign-in
```

The code page says the same thing whether or not an account has that name. The
code is queued in the outbox when it is asked for, and made when the outbox
sends it. So the page never waits on mail, which would make an account's answer
slower than a stranger's.

Between its two steps, the page keeps a cookie sealed under the root key. For a
name nobody has, the cookie holds random ids of the same length, so it tells its
holder nothing either. A signed token would have shown the account's id. That is
also why the emailed code is never offered without a root key.

It is not the second factor's code. It has its own table, its own mail, and its
own cookie. It never uses the pending sign-in token, which the second-factor
page accepts as a proved first factor.

Some sign-in pages name no organisation, such as the account page's in a
deployment with several. Such a page offers the code when some organisation's
flow takes it. The name then decides: the code goes to the one account the name
holds, if that account's organisation takes emailed codes. A name held in more
than one organisation gets no code from such a page, as the password form will
not choose between them.

These are the limits on a sign-in code:

| | |
|---|---|
| lifetime | 10 minutes |
| codes asked for, per account | one a minute and five an hour; past that, the code already sent stays the one that works, in the browser that asked for it |
| taken in | the browser that asked for it: the code page's cookie carries that request's id, and a code another browser asked for is no code there |
| codes asked for, per address | twenty an hour |
| attempts per code | 5, and each wrong one is also charged to the account's second-factor budget |
| stored as | SHA-256, compared in constant time, deleted when used |

The session records `amr` `otp` and `acr` `1`: one factor, possession of the
mailbox. `proved_by_password` is false for it. So
`{stage: mfa, when: proved_by_password}` does not ask, but
`when: proved_by_email` or `when: user_has_second_factor` does.

**The mailbox is one factor however many codes go to it.** After an emailed
sign-in code, email as a second factor is not counted for
`user_has_second_factor`. It is not sent, and not accepted on the code page. So
someone whose only second factor is email gets a one-factor session, not a
second code to the same inbox. An authenticator app, a text message, a security
key or Duo still count.

The sessions page shows such a sign-in as "Signed in with a code sent by email".
The built-in unenrolment flow accepts it, so someone who signs in no other way
can still delete their own account.

It is worth exactly what the mailbox is worth, as with the second factor. Offer
it where the people signing in would otherwise reuse a weak password, and not as
a step up from one.

## Verified end to end

These cases were checked against the running engine:

| | |
|---|---|
| enrol, wrong confirmation code | refused |
| enrol, correct code | enrolled, code consumed |
| sign in | challenged, code sent |
| submit the emailed code | session created |
| five wrong codes | `attempts` 1, 2, 3, 4, 5 |
| the **correct** code after those five | refused — the budget is gone until a new code is requested |

Codes are generated with `rand.Int` over the full range, not modulo over a
random byte. A six-digit code has only a million values, so the distribution
*is* the entropy. A test asserts that leading zeros survive. Otherwise one
person in ten would be handed a five-digit code.
