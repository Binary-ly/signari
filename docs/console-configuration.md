# Configuration screens in the console

SAML providers, external sign-in providers, groups, SCIM targets and admin tokens
now have screens. Everything they show was already working and was **CLI-only** —
so an operator who wanted to know what was configured had to SSH somewhere, which
means in practice nobody looked, and the half-configurations `signari doctor`
reports are exactly the ones that go unnoticed for months.

| Screen | Answers |
| --- | --- |
| SAML providers | which are registered, and which are half-configured |
| Sign-in providers | which are enabled, and whether sign-up can actually succeed |
| Groups | membership, and who the group is released to |
| Provisioning | whether SCIM is writing, and who is still active downstream |
| Admin tokens | scopes, expiry, last use — for this organisation only |

## Read-only, on purpose

These are views in `core_v1`, read through Eloquent models whose `save()` throws.
The console has no privilege on schema `core` at all (ADR-004), and writes still
go through the engine's Admin API or the CLI. Adding a second write path that
could disagree with the engine would undo the thing that makes the boundary
worth having.

That boundary is not theoretical. The first version of the test for these screens
queried `core.saml_providers` directly to find a fixture, and PostgreSQL refused
it — `permission denied for schema core`. The test was rewritten to go through
the scoped view like everything else.

## The gap this surfaced

**`core.admin_tokens` had no row-level security.** Every other tenant table has
it `FORCE`d; that one was added without it. Nothing was exposed while the table
was engine-only, but the moment the console reads it, a missing policy means one
tenant's screen lists every tenant's credentials by name and scope.

Now:

```sql
CREATE POLICY admin_tokens_org_isolation ON core.admin_tokens
    USING (core.is_engine() OR org_id = core.current_org_id())
```

`core.is_engine()` is load-bearing. The engine looks a token up **before** it
knows which organisation the caller belongs to — that is the entire point of the
lookup — so it has no org context to match against. Without the bypass every
admin request would 401, and the failure would read as a credential problem
rather than a policy one. Verified both directions after adding it:

```
engine authenticating a database token   -> 200
console with no org context              -> 0 rows       (fails closed)
console scoped to org A                  -> A's 2 tokens
console scoped to org B                  -> 0 of A's
deployment-wide tokens (org_id NULL)     -> invisible to any tenant
```

Deployment-wide tokens are hidden deliberately: listing one for a tenant would
disclose that another tenant is reachable with it.

The secret is never in the view — there is no path in this system that reveals a
token after it is minted, and a test asserts the view exposes no column named
`token`, `token_hash` or `secret`.

## What the screens are for

Each one leads with **state**, not with a list, because the reason to open them is
almost always "is anything broken":

- a SAML provider that requires signed AuthnRequests with **no certificate on
  file** refuses every login, and looks correct in every individual column
- a generic OIDC provider that allows sign-up **without trusting its email
  verification** refuses every sign-up
- a SCIM target in **dry run** looks configured, reports no errors and writes
  nothing
- an admin token that **expires in nine days** takes the console down at 3am

Navigation badges count the misconfigured rows, not the total. A badge showing
"1,204 groups" is decoration; one showing "2" next to a warning is a number to
act on.

Group releases match on the group **name**, so `released_to_clients` and
`released_to_saml` are shown on the groups screen — renaming a group silently
removes it from every allow-list that mentioned it, and nothing errors.

## Tested with rows in them

An empty list evaluates no column closures at all, so a screen that 500s the
moment real data appears looks perfectly healthy until the day it is needed. That
has already happened once in this console, with three closures whose parameters
Filament could not inject. So the tests assert a real provider's entity id is
visible, not merely that the page returns 200 — and separately that an operator
in another organisation, or in none, cannot see it.
