# Support access

## Introduction

Sometimes an administrator needs to see exactly what a person sees, such as when
Ada reports that the wiki shows her the wrong page. "Support access", also called
"impersonation", lets an administrator act as Ada for a short time, **visibly**.

Signari puts the administrator's identity in every token made during support
access, so each application can tell who really acted. Its rules are refusals,
not log lines, and each episode is recorded against both people.

An administrator starts support access from their own signed-in session. They
can do so only if they are in a group that holds the capability, and by default
no group does.

## Starting and stopping

These two requests start support access as a person, with the reason for it, and
stop it again:

```
POST /admin/impersonate        user=<uuid>  reason=<why>
POST /admin/impersonate/stop
```

In this example, `<uuid>` is the ID of the person to act as. The administrator
doing the acting is taken from the session that sends the request, never from
the request itself.

## The difference that matters

The failure this avoids is the *unconfigured* one. Suppose support access were
marked only for applications given a claim mapper for it. An application that
was never given one would see a token indistinguishable from Ada's own.

Its audit trail, the one where any damage would be done, would then record
**Ada** as having acted, and she cannot prove otherwise. An audit property
that depends on each application's configuration is an audit property some
application does not have.

So a session started here carries the administrator's identity in **every token
minted from it**, as the `act` claim:

```json
{ "sub": "387ba966-…", "act": { "sub": "551049cd-…" } }
```

In this example, `sub` is the person being acted as, and `act` names the
administrator acting for them.

`act` is on the access token as well as the ID token, regardless of scope. An
API call made during support access is exactly the case where the API needs to
know. An application can refuse the request, label the record, or write its own
log entry naming the real actor, without having to trust Signari's log.

This was verified against a running engine. Both tokens carry `act`, and an
ordinary sign-in by the same administrator carries none. A claim that is always
present says nothing.

## The rules, each a refusal rather than a log line

Each rule below is enforced by refusing. One of them mentions row-level security
([RLS](glossary.md#rls)), the database rule that keeps organisations apart.

| | |
|---|---|
| **Nobody may, by default** | A capability on a group (`may_impersonate`), granted to nobody. A feature arriving switched on for whoever is in a group called "admins" is a privilege escalation delivered by an upgrade |
| **Granting it takes database credentials** | `signari group impersonation -org <uuid> -group <name> -grant`. Deliberately **not** in the Admin API: a `groups:write` token is issued for day-to-day administration, and letting one confer impersonation would turn every such token into a way to become anybody. The API reports which groups hold it and refuses to set it, on create and on patch alike. Joining or leaving such a group through the API, and writes on its members, need `privileged-users:write` as well ([groups in the Admin API](admin-api.md#groups)) |
| **Never another administrator** | Nobody who may impersonate can be impersonated. Acting as another administrator gives the actor that administrator's reach too, and the episode would be recorded as a support visit when it was a takeover |
| **A reason is required** | And stored. An organisation that cannot answer "why was this account accessed" does not have support access, it has a back door |
| **Never yourself** | Impersonating yourself launders an action into an unattributable one |
| **Never across organisations** | RLS does *not* catch this — the engine is exempt by design and this runs as the engine |
| **Never chained** | An impersonated session cannot start another, or the actor recorded is the person being impersonated |
| **It ends by itself** | 30 minutes, enforced by the janitor. Support access nobody remembered to close is a live administrative session wearing somebody else's name |
| **It changes no way in** | An impersonated session cannot add, replace, move or remove a factor, register or delete a passkey, link or unlink an external account, or regenerate recovery codes. It is refused with 403 on every one of those routes. Support exists to see what the person sees, and a credential the administrator enrolled would outlast the episode |

## Session handling

The `acr` and `amr` claims describe how the **administrator** authenticated,
because that is what actually happened. The `acr` is the Authentication Context
Class Reference ([ACR](glossary.md#acr)), and `amr` lists the methods used.

Copying the subject's would claim a factor nobody performed. A step-up
requirement, which asks for a stronger sign-in, would then be satisfied by an
authentication that never took place.

The cookie is bounded by the **episode**, not the ordinary session lifetime. An
eight-hour cookie for thirty minutes of support access outlives its own
authorisation.

The administrator signs in again as themselves rather than being restored.
Restoring automatically would mean keeping an administrative session alive
throughout. A dormant one is what an attacker reaching this browser wants to
find.

## Audit

`impersonation.started` is recorded against **both** people. An investigation
starts from whichever name it has. A trail found only from the administrator's
side is one the person cannot use to find out what happened to their own
account.

`impersonation.refused` is recorded too, because an attempt that failed the
capability check is worth knowing about.
