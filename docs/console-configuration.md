# Configuration screens in the console

## Introduction

An administrator often needs to know what is configured, and whether any of it
is broken. The console now has screens for groups, admin tokens and external
sign-in providers. It also has screens for Security Assertion Markup Language
([SAML](glossary.md#saml)) providers and System for Cross-domain Identity
Management ([SCIM](glossary.md#scim)) targets.

Everything those screens show was already working and was **CLI-only**: you could
see it only from the command-line interface (CLI). An administrator who wanted to
know what was configured had to connect to a server over Secure Shell (SSH). In
practice nobody looked, and the half-configurations `signari doctor` reports are
exactly the ones that go unnoticed for months. Each screen now leads with what is
wrong.

> [!NOTE]
> The screens are views. The few actions on them, like every other change, go
> through the engine's [Admin API](admin-api.md).

## The screens

The console has a screen for each of these, and each answers one question:

| Screen | Answers |
| --- | --- |
| SAML providers | which are registered, and which are half-configured |
| Sign-in providers | which are enabled, and whether sign-up can actually succeed |
| Groups | membership, and who the group is released to |
| Provisioning | whether SCIM is writing, and who is still active downstream |
| Admin tokens | scopes, expiry, last use — for this organisation only |
| Relations | who holds what on what, directly and in force. A relation held through a parent or a team has no row of its own, and the screen says so |
| Authorization model | the file in force, as it was written. None means nothing is permitted, which is worth seeing before an application reports it |
| Scopes, Attributes, Claim mappers | what the organisation declares, so a token's contents can be read without a configuration file to hand |
| Directories, Inbound SCIM | where people come from, and how the last sync went. Credentials are not in the views |
| Sign-in journeys | every path through the flow in force, from the engine's own walker |
| Brand, Messages | what its [pages look like](brands.md#an-organisations-own) and [say](brands.md#an-organisations-words) |
| Sessions, Audit trail | who is signed in, and what happened |

Some screens act. They act through the Admin API, held to the configuration
version the page showed. If someone made a change after the page loaded, the
action is refused rather than made over it:

- **End session** on a session;
- **Add a member** and **Remove a member** on a group, which find the person by
  address among the organisation's own people;
- **Erase** on a person, which asks for their address as well as a yes, and needs
  `subjects:erase`.

The console is one organisation's. There is no organisation switcher, because the
organisation a request is scoped to comes from the administrator's own record. A
selector the caller could set would be no boundary. Work across organisations is
done through the Admin API.

## Signing in to the console

Administrators can sign in to the console through Signari itself, with a second
factor, once the console's settings name the issuer and the console's own client
(`SIGNARI_ISSUER` and `SIGNARI_CONSOLE_CLIENT_ID`). A password then admits only the
break-glass account, which is the way in when Signari is what is down. [Signing in
to the console through Signari](admin-tokens.md#signing-in-to-the-console-through-signari)
sets it up.

Without those settings, administrators sign in with the console's own accounts. An
account that signs in with a password, including the break-glass account, has a
second factor of its own, an authenticator app. Setting it up, replacing it or
removing it ends every other session that account holds in the console, and every
remember-me cookie issued before.

> [!NOTE]
> Open sessions are ended only with the console's default
> `SESSION_DRIVER=database`. With another driver, the remember-me cookies are
> still ended, but open sessions run until they expire.

## Read-only, on purpose

The screens read views in `core_v1`, through Eloquent models whose `save()`
throws. Eloquent is Laravel's database layer, and the console is a Laravel
application. The console has no privilege on schema `core` at all (architecture
decision record ADR-004). Writes still go through the engine's Admin API or the
CLI. A second write path that could
disagree with the engine would undo the thing that makes the boundary worth
having.

That boundary is not theoretical. The first version of the test for these screens
queried `core.saml_providers` directly to find a fixture, and PostgreSQL refused
it: `permission denied for schema core`. The test was rewritten to go through the
scoped view like everything else.

## The gap this surfaced

**`core.admin_tokens` had no row-level security.** Every other table that holds an
organisation's data has it `FORCE`d, and that one was added without it. Nothing
was exposed while only the engine read the table. The moment the console reads
it, though, a missing policy means one organisation's screen lists every
organisation's credentials, by name and scope.

The table now has this policy:

```sql
CREATE POLICY admin_tokens_org_isolation ON core.admin_tokens
    USING (core.is_engine() OR org_id = core.current_org_id())
```

`core.is_engine()` is load-bearing. The engine looks a token up **before** it
knows which organisation the caller belongs to. Finding that out is the entire
point of the lookup, so the engine has no organisation to match against. Without
the bypass, every Admin API request would fail with 401, and the failure would
read as a credential problem rather than a policy one.

Both directions were verified after the policy was added:

```
engine authenticating a database token   -> 200
console with no org context              -> 0 rows       (fails closed)
console scoped to org A                  -> A's 2 tokens
console scoped to org B                  -> 0 of A's
deployment-wide tokens (org_id NULL)     -> invisible to any tenant
```

Deployment-wide tokens are hidden deliberately. Listing one for an organisation
would disclose that another organisation is reachable with it.

The secret is never in the view. There is no path in this system that reveals a
token after it is minted. A test asserts that the view exposes no column named
`token`, `token_hash` or `secret`.

## What the screens are for

Each one leads with **state**, not with a list, because the reason to open them is
almost always "is anything broken". These are the problems they put first:

- Take a SAML provider that requires signed authentication requests, called
  "AuthnRequests", with **no certificate on file**. It refuses every sign-in, and
  looks correct in every individual column.
- A generic OpenID Connect ([OIDC](glossary.md#oidc)) provider that allows sign-up
  **without trusting its email verification** refuses every sign-up.
- A SCIM target in **dry run** looks configured, reports no errors and writes
  nothing.
- An admin token that **expires in nine days** takes the console down at 3am.

Navigation badges count the misconfigured rows, not the total. A badge showing
"1,204 groups" is decoration. One showing "2" next to a warning is a number to act
on.

Group releases match on the group's **name**, so the groups screen shows
`released_to_clients` and `released_to_saml`. Renaming a group silently removes it
from every allow-list that mentioned it, and nothing reports an error.

## Tested with rows in them

An empty list evaluates no "column closures" at all: the functions that fill each
column only run when there is a row. So a screen that fails with a 500 error the
moment real data appears looks perfectly healthy until the day it is needed.

That has already happened once in this console, with three closures whose
parameters Filament, the library the console's screens are built with, could not
inject. So the tests
assert that a real provider's entity ID is visible, not merely that the page
returns 200. Separately, they assert that an administrator in another
organisation, or in none, cannot see it.
