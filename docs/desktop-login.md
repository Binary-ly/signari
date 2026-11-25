# Desktop and workstation sign-in

## Introduction

Some sign-in screens are not web pages. A Windows credential provider, a pluggable
authentication module (PAM) or a kiosk draws its own sign-in box. It needs a
yes-or-no answer in one exchange.

Signari gives that answer at `/outpost/desktop`. The program sends what the person
typed: a username, a password and, when one is needed, a code. Signari replies
whether the person is signed in.

You create an outpost of the `desktop` kind with `signari outpost create`, and the
program sends that outpost's token with every request.

## Check a person at a desktop

Create an outpost of the `desktop` kind:

```sh
signari outpost create -org <uuid> -name workstations -kind-outpost desktop
```

The program then posts what the person typed, with the outpost's token:

```http
POST /outpost/desktop
Authorization: Bearer <outpost token>

{"username": "alice@example.com", "password": "…", "code": "123456"}
```

When everything is right, Signari answers with the person and how they proved who
they are:

```json
{"result": "authenticated", "user": "alice@example.com", "amr": ["pwd", "otp"]}
```

## What Signari ships, and what it does not

Signari ships **this endpoint**. The Windows side is a Credential Provider: a
Component Object Model (COM) dynamic-link library (DLL), registered with Winlogon,
written in C++ and code-signed. A Go identity engine does not ship one. Saying
otherwise would be exactly the kind of claim this project exists to avoid.

What is here is the half that belongs to an identity provider. It is also the half a
PAM module needs. So `pam_exec` calling this is a **working Linux desktop sign-in
today**, with no additional component.

## Why it is not the ordinary sign-in flow

The web flow is a sequence of pages, with a signed pending token between them. That
is right for a browser, and impossible for Winlogon, which cannot render a page and
cannot follow a redirect.

So this endpoint answers in one exchange. Where a second factor is required, it says
so rather than refusing:

```json
{"result": "second_factor_required",
 "prompt": "Enter the code from your authenticator"}
```

A plain refusal would leave the dialog with no way to know it should show a second
box.

## MFA cannot be sidestepped by signing in at a desktop

Whether a second factor is required is decided by the sign-in flow. It is the same
question that Lightweight Directory Access Protocol ([LDAP](glossary.md#ldap)) and
Remote Authentication Dial-In User Service ([RADIUS](glossary.md#radius)) ask.

Enrol an authenticator, and the desktop path demands it from the next attempt. This
was verified by enrolling one and watching the same correct password stop being
sufficient.

Under a flow whose `mfa` stage runs for everybody, a person with nothing enrolled is
refused at the desktop, as at the sign-in page. No code they could type would be
right. That case used to sign in on the password alone, because the desktop asked
only whether a factor was enrolled.

`password_only_binds` does not apply here. It exists for protocols that cannot carry
a code, and this one can.

It carries a code and nothing else. A person whose only second factor is a security
key or passkey is asked for a code here. The only code that can be right is one of
their recovery codes.

An emailed or texted code cannot be used either. Each is taken only for the sign-in
it was sent for, and this exchange sends none (see [email
codes](email-otp.md#one-live-code-never-a-queue-of-them)). Until November 2026 one
sent for a browser's sign-in was taken here.

## Its own outpost kind

A `desktop` token verifies a **second factor** as well as a password. That is
strictly more than an LDAP or RADIUS outpost can do. An LDAP token presented here is
refused:

```
this token was issued for a ldap outpost. Desktop login verifies a second factor
as well as a password, so it needs a token issued for it
```

A token worth more should not be issued to something that needs less.

## One answer for every failure

A wrong password, an unknown username and a missing credential all return the same
`authentication refused`. An outpost sits somewhere less trusted, by definition.
Telling the failures apart there would make it an endpoint for finding out which
accounts exist, on a workstation.

They take the same time too: each refusal spends one password hash, as a wrong
password does. Until October 2026 the others were answered before any hashing, so
the time of the reply told them apart.

Each failure is charged to the account's sign-in budget. It is the one the sign-in
page and LDAP draw on: 30 failures in 15 minutes. The attempt past it is refused with
`429` before any hashing, and a right password costs nothing.

Until October 2026 the desktop charged nothing. So an outpost token could spend its
whole allowance of calls guessing one person's password.

Every attempt, successful or not, is written to the audit trail with the outpost that
made it.

## What has been verified, and what has not

These were verified against a running engine:

- A correct password authenticates.
- A wrong one, and an unknown username, return the identical refusal.
- An LDAP token is refused.
- Enrolling an authenticator makes the same correct password insufficient.

**Not verified:** the wrong-second-factor path, end to end. The test credential was
a placeholder the root key could not unseal. So that attempt returned a server error
rather than a refusal. That is correct, since a credential that cannot be opened
*is* a server problem. But it means the refusal path itself is covered only by the
browser flow's tests, not by this endpoint's.

**Not shipped:** the Windows credential provider.
