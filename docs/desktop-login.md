# Desktop and workstation login

A Windows credential provider, a PAM module, a kiosk — anything that draws its
own login box and needs a yes-or-no answer in one exchange.

```sh
signari outpost create -org <uuid> -name workstations -kind-outpost desktop
```

```http
POST /outpost/desktop
Authorization: Bearer <outpost token>

{"username": "alice@example.com", "password": "…", "code": "123456"}
```

```json
{"result": "authenticated", "user": "alice@example.com", "amr": ["pwd", "otp"]}
```

## What Signari ships, and what it does not

**This endpoint.** The Windows side is a Credential Provider — a COM DLL
registered with Winlogon, written in C++ and code-signed — and a Go identity
engine does not ship one. Saying otherwise would be exactly the kind of claim
this project exists to avoid.

What is here is the half that belongs to an identity provider. It is also the
half a PAM module needs, so `pam_exec` calling this is a **working Linux desktop
login today**, with no additional component.

## Why it is not the ordinary sign-in flow

The web flow is a sequence of pages with a signed pending token between them.
That is right for a browser and impossible for Winlogon, which cannot render a
page and cannot follow a redirect.

So this answers in one exchange — and where a second factor is required, it says
so rather than refusing:

```json
{"result": "second_factor_required",
 "prompt": "Enter the code from your authenticator"}
```

A plain refusal would leave the dialog with no way to know it should show a
second box.

## MFA cannot be sidestepped by signing in at a desktop

Whether a second factor is required is decided by the same function the browser
flow uses. Enrol an authenticator and the desktop path demands it from the next
attempt — verified by enrolling one and watching the same correct password stop
being sufficient.

## Its own outpost kind

A `desktop` token verifies a **second factor** as well as a password, which is
strictly more than an LDAP or RADIUS outpost can do. An LDAP token presented
here is refused:

```
this token was issued for a ldap outpost. Desktop login verifies a second factor
as well as a password, so it needs a token issued for it
```

A token worth more should not be issued to something that needs less.

## One answer for every failure

A wrong password, an unknown user and a missing credential all return the same
`authentication refused`. An outpost sits somewhere less trusted by definition,
and distinguishing them there is a user-enumeration endpoint on a workstation.

Every attempt, successful or not, is written to the audit trail with the outpost
that made it.

## What has been verified, and what has not

Verified against a running engine: a correct password authenticates, a wrong one
and an unknown user return the identical refusal, an LDAP token is refused, and
enrolling an authenticator makes the same correct password insufficient.

**Not verified:** the wrong-second-factor path end to end. The test credential
was a placeholder the root key could not unseal, so that attempt returned a
server error rather than a refusal — correctly, since a credential that cannot
be opened *is* a server problem, but it means the refusal path itself is covered
only by the browser flow's tests rather than by this endpoint's.

**Not shipped:** the Windows credential provider.
