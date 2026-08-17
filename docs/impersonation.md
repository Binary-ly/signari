# Support access

An administrator acting as a user, **visibly**.

```
POST /admin/impersonate        user=<uuid>  reason=<why>
POST /admin/impersonate/stop
```

## The difference that matters


The failure mode we are avoiding is the *unconfigured* one. A relying party that
was never given a mapper sees a token indistinguishable from the user's own, so
the audit trail in the application — the one where the damage would be done —
records the **user** as having acted, and they cannot prove otherwise. An
audit property that depends on per-client configuration is an audit property
some client does not have.

A session started here carries the administrator's identity in **every token
minted from it**, as `act`:

```json
{ "sub": "387ba966-…", "act": { "sub": "551049cd-…" } }
```

On the access token as well as the ID token, and regardless of scope — an API
call made during support access is exactly the case where a resource server needs
to know. A relying party can refuse the request, label the record, or write its
own log entry naming the real actor, without having to trust our log.

Verified against a running engine: both tokens carry `act`, and an ordinary
sign-in by the same administrator carries none. A claim that is always present
says nothing.


## The rules, each a refusal rather than a log line

| | |
|---|---|
| **Nobody may, by default** | A capability on a group (`may_impersonate`), granted to nobody. A feature arriving switched on for whoever is in a group called "admins" is a privilege escalation delivered by an upgrade |
| **A reason is required** | And stored. An organisation that cannot answer "why was this account accessed" does not have support access, it has a back door |
| **Never yourself** | Impersonating yourself launders an action into an unattributable one |
| **Never across organisations** | RLS does *not* catch this — the engine is exempt by design and this runs as the engine |
| **Never chained** | An impersonated session cannot start another, or the actor recorded is the person being impersonated |
| **It ends by itself** | 30 minutes, enforced by the janitor. Support access nobody remembered to close is a live administrative session wearing somebody else's name |

## Session handling


`acr`/`amr` describe how the **administrator** authenticated, because that is what
actually happened. Copying the subject's would claim a factor nobody performed,
and a step-up requirement would then be satisfied by an authentication that never
took place.

The cookie is bounded by the **episode**, not the ordinary session lifetime. An
eight-hour cookie for thirty minutes of support access outlives its own
authorisation.


The administrator signs in again as themselves rather than being restored.
Restoring automatically would mean keeping an administrative session alive
throughout, and a dormant one is what an attacker reaching this browser wants to
find.

## Audit

`impersonation.started` is recorded against **both** people. An investigation
starts from whichever name it has, and a trail findable only from the
administrator's side is one the user cannot use to find out what happened to their
own account. `impersonation.refused` is recorded too — an attempt that failed the
capability check is worth knowing about.
