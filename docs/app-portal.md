# The application portal

## Introduction

An organisation often has many applications, and a person may not know which
ones they can use. A "portal" is one page that lists them, so the person can
open each one from there.

Signari's portal is at `/apps`. It shows a signed-in person what they can
reach, and why they cannot reach the rest.

Your [access policy](policy.md) decides what each person can reach. Flags on
`signari client create` decide how each application appears on the portal, or
whether it appears at all.

## What a person sees

A person signed in at Acme might see a portal like this:

```
Your applications

  [ Company Wiki ]   [ Expenses ]   [ Reporting Tool ]
                                    You can use this, but no launch
                                    address is configured.

Not available to you

  Payroll      Payroll is limited to the finance group. Ask your
               manager to be added.
  Legacy CRM   The legacy CRM needs a passkey. Add one under your
               account settings.
```

## Access is decided live, not assigned

Signari does not store application access as an "assignment", a table saying Ada
may use Payroll. It has no such table, and the absence is deliberate.

The portal is rendered through the **access policy**, the same file that
governs every other authorization decision. So a tile can depend on things an
assignment table cannot express:

- which network the request came from;
- whether the device is managed;
- whether the session used a passkey;
- the time of day.

The list a person sees is the list they can actually open at that moment. It is
not a list of things they are nominally entitled to, and may still be refused.

It also means there is one place to look. An assignment table and a policy
engine will eventually disagree. When they do, nobody can tell you which one is
in force.

## Why blocked applications are shown

Signari shows them because the alternative is a support ticket.

Suppose the portal silently left out an application a person cannot reach.
*"How do I get into Payroll?"* would become a question an administrator answers
by hand. Yet the system already knows the answer, and would only have declined to
say it. That is the most common identity support burden there is, and it exists
only because the product chose not to speak.

So a blocked application is listed with the reason. The reason is taken from
the policy's own `message` field, which is written for the person being
refused:

```yaml
- name: payroll-needs-the-finance-group
  when: {client: portal-payroll}
  require: {groups: [finance]}
  message: Payroll is limited to the finance group. Ask your manager to be added.
```

Write that message for the person who reads it, not for yourself. It is all
that person ever sees of your access policy.

## The trade this makes, stated plainly

Listing a blocked application tells the person that the application exists.

For most organisations, that is not a secret. People know their employer runs a
payroll system, and knowing its name gets nobody any closer to it. Where it *is*
a secret, keep the application off the portal entirely:

```sh
signari client create -client-id skunkworks … -portal-hidden
```

This is a real trade, not a default that is right for everyone. That is why it
is configurable, and why the reasoning is written down here instead of being
assumed.

## Registering an application for the portal

To give an application a tile, register it with a launch address and,
optionally, a logo. Signari's commands call an application a "client":

```sh
signari client create \
  -client-id wiki \
  -name "Company Wiki" \
  -redirect https://wiki.example.com/oauth/callback \
  -launch-url https://wiki.example.com/ \
  -logo-url https://wiki.example.com/logo.svg
```

The portal reads three flags:

| Flag | |
|---|---|
| `-launch-url` | Where the portal sends the person. Must be https |
| `-logo-url` | Optional, https only |
| `-portal-hidden` | Keep this client off the portal entirely |

**`-launch-url` is the application's own address, not Signari's.** It maps to
the OpenID Connect registration field `initiate_login_uri`, which exists for
exactly this. Sign-in begins at the *application*, so the application's own
state survives. Suppose a tile pointed at Signari's authorization endpoint
instead. Its link would sign the person in, then drop them on a blank dashboard
instead of the page they wanted.

An application with no launch address is still listed, marked as unlaunchable.
Hiding it would hide the mistake. The person best placed to notice is the
administrator, and they will not see it if the portal quietly leaves it out.

[Security Assertion Markup Language (SAML)](saml.md) calls an application a
"service provider". A SAML application has a tile once
`signari saml idp-initiated` opts it in. The portal asks the policy about it by
its entity ID. Its tile starts the sign-in here, because that is what a
provider with no sign-in page of its own needs. See
[a sign-in that starts here](saml.md#a-sign-in-that-starts-here).

## What never appears

Three kinds of application never appear on the portal:

- disabled applications, since their tile would refuse whoever clicks it;
- applications marked `-portal-hidden`;
- applications that cannot start a browser flow.

That last one matters more than it looks. Machine-to-machine applications are
service accounts. A portal that listed them would publish the organisation's
internal service inventory to every employee. Existing applications without
the authorization code grant were hidden by the migration that introduced this,
so upgrading does not suddenly disclose anything.

Each of those exclusions has a test. Each test was checked by removing the
condition and confirming that the test noticed.
