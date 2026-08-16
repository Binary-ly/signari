# The application portal

`/apps` — what a signed-in user can reach, and why not the rest.

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

Every other product in this field stores application access as an assignment:
a table saying Alice may use Payroll. Signari does not have that table, and the
absence is deliberate.

The portal is rendered through the **access policy**, the same file that governs
every other authorization decision. That means a tile can depend on things an
assignment table cannot express — which network the request came from, whether
the device is managed, whether the session used a passkey, the time of day. The
list a user sees is the list they can actually open at that moment, not a list
of things they are nominally entitled to and may still be refused.

It also means there is one place to look. An assignment table and a policy
engine will eventually disagree, and when they do, nobody can tell you which one
is in force.

## Why blocked applications are shown

Because the alternative is a support ticket.

Silently omitting an application a user cannot reach turns *"why can't I get
into Payroll?"* into a question an administrator has to answer by hand — and the
answer is something the system already knows and has just declined to say. That
is the most common identity support burden there is, and it exists only because
the product chose not to speak.

So a blocked application is listed with the reason, taken from the policy's own
`message` field, which is written for the person being refused:

```yaml
- name: payroll-needs-the-finance-group
  when: {client: portal-payroll}
  require: {groups: [finance]}
  message: Payroll is limited to the finance group. Ask your manager to be added.
```

Write that message for the user, not for yourself. It is the entire user-facing
surface of your access policy.

## The trade this makes, stated plainly

Listing a blocked application tells the user that application exists.

For most estates that is not a secret — people know their employer runs a
payroll system, and knowing its name gets nobody any closer to it. Where it *is*
a secret, keep the client off the portal entirely:

```sh
signari client create -client-id skunkworks … -portal-hidden
```

This is a real trade rather than an obviously correct default, which is why it
is configurable and why the reasoning is written down here instead of being
assumed.

## Registering an application for the portal

```sh
signari client create \
  -client-id wiki \
  -name "Company Wiki" \
  -redirect https://wiki.example.com/oauth/callback \
  -launch-url https://wiki.example.com/ \
  -logo-url https://wiki.example.com/logo.svg
```

| Flag | |
|---|---|
| `-launch-url` | Where the portal sends the user. Must be https |
| `-logo-url` | Optional, https only |
| `-portal-hidden` | Keep this client off the portal entirely |

**`-launch-url` is the application's own address, not ours.** It maps to the
OpenID Connect `initiate_login_uri` registration field, which exists for exactly
this: login begins at the *application* so the application's own state survives.
Pointing a tile at our authorize endpoint instead produces a link that signs the
user in and drops them on a blank dashboard rather than the page they wanted.

An application with no launch URL is still listed, marked as unlaunchable.
Hiding it would hide the mistake; the person best placed to notice is the
administrator, and they will not see it if the portal quietly omits it.

## What never appears

- disabled clients — a tile that refuses whoever clicks it
- clients marked `-portal-hidden`
- clients that cannot start a browser flow

That last one matters more than it looks. Machine-to-machine clients are service
accounts, and a portal listing them publishes the organisation's internal
service inventory to every employee. Existing clients without the authorization
code grant were hidden by the migration that introduced this, so upgrading does
not suddenly disclose anything.

Each of those exclusions has a test that was checked by removing the condition
and confirming the test noticed.
