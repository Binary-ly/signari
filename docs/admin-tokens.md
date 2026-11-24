# Admin API access

## Introduction

Every program that changes Signari through the [Admin API](admin-api.md) needs a
credential. The console needs one, and so does a deployment script or a
monitoring check. A script that reads a version number has no use for a
credential that can delete people.

Signari gives each program its own "admin token". A token's "scopes" name what it
may do. It belongs to one organisation unless it is made without one, and it can
be narrowed further to named applications, groups or attributes. It expires after
ninety days unless you say otherwise, and it can be revoked at once. Every change
made with it is recorded against it in the audit trail.

You make tokens with `signari admin-token` on the command line, or over the Admin
API itself. The console can also sign its administrators in through Signari, so
that each acts with a role of their own instead of a shared token.

## Making a token

This creates a token for the console that may write people and applications and
read the configuration version, for 90 days. It then lists the tokens, and
revokes one by its ID:

```sh
signari admin-token create \
  -name "laravel console (prod)" \
  -org  <org-uuid> \
  -scopes users:write,clients:write,config:read \
  -expires-in 2160h            # 90 days

signari admin-token list
signari admin-token revoke -token-id <uuid>
```

## What this replaced

Admin tokens replaced one token, in an environment variable, that granted
everything, in every organisation, forever. That had three separate problems, and
the third is the one that matters:

| | |
| --- | --- |
| **revocation** | changing it meant restarting every node, so in practice nobody rotated it and a leaked token stayed valid indefinitely |
| **attribution** | every change in the audit trail was attributed to "the admin token", which is the same as no attribution |
| **blast radius** | the console needs to write users and clients; a monitoring script needs to read a version number. Both got the same unlimited credential, and either one leaking lost every tenant |

## Scopes

A scope names a set of endpoints a token may call. There are deliberately few. A
permission model nobody can hold in their head gets granted wholesale, which is
exactly the situation being replaced.

Each scope opens these endpoints:

| scope | endpoints |
| --- | --- |
| `users:read` | `GET /admin/users`, `GET /admin/users/{id}`, and a user's sessions |
| `users:write` | `POST /admin/users`, `PATCH /admin/users/{id}`, `DELETE /admin/users/{id}`, removing second factors, and ending sessions |
| `clients:read` | `GET /admin/clients`, `GET /admin/clients/{id}` |
| `clients:write` | `POST /admin/clients`, `PATCH /admin/clients/{id}`, rotate-secret |
| `groups:read` | `GET /admin/groups`, one group, and its members |
| `groups:write` | Create, rename, delete a group; add and remove members |
| `config:read` | `GET /admin/config-version` |
| `subjects:erase` | `POST /admin/subjects/{id}/erase` |
| `subjects:export` | `GET /admin/subjects/{id}/export`: everything kept about one person. **Not implied by any other scope** — see below |
| `organizations:write` | `POST /admin/organizations`. Useless to an organisation-scoped token — see below |
| `audit:read` | `GET /admin/audit-events`. **Not implied by any write scope** — see below |
| `privileged-users:write` | Needed as well as the route's own scope to write on a user who may impersonate, or on a group that confers it (including its membership). See [groups in the Admin API](admin-api.md#groups) |
| `relations:read` | `GET /admin/organizations/{orgID}/relations` |
| `relations:write` | Grant and revoke relations, and nothing else about the organisation, for an application that keeps its own. `organizations:write` satisfies both |
| `tokens:read` | `GET /admin/tokens` |
| `tokens:write` | `POST /admin/tokens`, rotate and revoke, each only for a token no wider than the caller — see below |

**A write scope implies the matching read scope.** `clients:write` can read a
client without also being granted `clients:read`. A token that may change a thing
has no reason to be blind to it. Requiring both would also have silently removed
access from every token already issued, the day read endpoints appeared. The
implication runs one way only: a read scope never grants a write.

**Groups get their own pair rather than riding on `users:*`.** A group decides
which applications its members reach. So granting the ability to edit membership
is granting application access, which is a different decision from being able to
reset a password.

**`subjects:erase` is separate from `users:write`** because a token that may
rename a person should not thereby be able to destroy one irreversibly.

**`subjects:export` is separate from `users:read`** for the reason `audit:read`
is. An export is all of one person at once: their sessions, what each application
was given and the trail of their account. A token that may look a person up
should not thereby be able to take all of that. See [exporting a person's
data](data-export.md).

**`privileged-users:write` is separate because the alternative is a ladder.**
Without it, a `users:write` token could change the email address of someone
who may [impersonate](impersonation.md). It could then recover their account. A
`groups:write` token could add the person who holds it to a group that may
impersonate.
Either way the lesser credential becomes the greater one. Only a few tokens need
this scope. Most do not, and they keep working on everyone else.

## Minting, rotating and revoking over the API

`POST /admin/tokens` mints a token, `POST /admin/tokens/{id}/rotate` replaces
one's secret, and `DELETE /admin/tokens/{id}` revokes one. **A token can do this
only for a token no wider than itself**, in every way a token can be wide:

- The scopes must be ones the caller holds.
- The organisation must be the caller's.
- The clients, groups and attributes must be among the caller's, so a
  client-narrowed caller cannot mint an unnarrowed token.
- The token cannot outlive the caller.

Rotation is held to the same rule, because rotating a token hands over a working
secret for it. A narrow token able to rotate a wide one would have become the
wide one. Revocation is held to it too, or a token for one client could revoke the
organisation's main credential. Every token may rotate or revoke itself.

A token minted over the API **always expires**: ninety days unless
`expires_in_s` says otherwise, at most a year. A rotation leaves the old secret
working for `grace_s`, so the replacement can be deployed first. That is a day
unless told, at most a week, and 0 for none.

`signari admin-token create` now gives ninety days too, unless `-expires-in` is
given. `-expires-in 0` is the deliberate way to make one that never expires. Until
October 2026 tokens never expired by default, and only the command-line interface
(CLI) could make or revoke one.

Minting, rotating and revoking are each audited: `admin.token_created`,
`admin.token_rotated` (naming the replacement), and `admin.token_revoked`.

## Narrowing a token to named objects

You can restrict a token to particular clients, groups or user attributes, not
only to a scope and an organisation. A continuous integration (CI) job that
deploys one application should not hold a credential able to disable the payroll
system.

Three fields narrow a token:

| | |
|---|---|
| `client_ids` | Clients this token may act on, for reads and writes alike. `GET /admin/clients` lists only these, and the token cannot create a client |
| `group_ids` | Groups it may act on, including their membership. `GET /admin/groups` lists only these, and the token cannot create a group |
| `attribute_names` | User attributes, by declared name, whose values it may read, set, clear or release (`-attributes` on `signari admin-token create`). `GET /admin/users/{id}/attributes` gives only these, and says nothing of the others, not even that the person has them. A name the organisation does not declare is refused when the token is made |

**Field-level access** (Application Security Verification Standard,
[ASVS](security-review-asvs.md) 5.0.0 V8.2.3). Before November 2026 `users:read`
read every attribute value a person held, personal ones unsealed. So a help desk's
lookup token read what a payroll integration's needed.

A token narrowed to attributes is refused what would reach the others another
way. A claim mapper releasing one, or deleting another's mapper, is refused. So
is a person's whole export (`GET /admin/subjects/{id}/export`), a configuration
file, an upstream's attribute map, and a role that reaches every attribute
(`user-manager`, say). Rotating the token keeps the narrowing.

**A narrowed token cannot create an object of the kind it is narrowed on.** The
new object would not be on its list. So the token could register an application,
with credentials and redirect URIs, that it is then forbidden to manage.
Narrowing on one kind does not affect the other: a token narrowed to named
clients can still create a group if it holds `groups:write`.

**Unset means every object**, which is what every token issued before this
existed carries. The restriction is opt-in, for the same reason
[`If-Match`](admin-api.md#conditional-writes) is.

**An empty list means *none*, not everything.** The two are deliberately
different. A `[]` that read as unrestricted is how a narrowing feature becomes a
widening one. It happens the first time somebody clears a list intending to
revoke access, and grants all of it instead.

Reads are narrowed as well as writes. A read boundary that does not match the
write boundary is one an integrator will find and use.

**Client IDs match exactly.** They are case-sensitive keys, so `app` and `APP` are
two clients, and a token for one cannot touch the other. The comparison was once
case-insensitive, and such a token could read and disable both. Group IDs are
universally unique identifiers (UUIDs), and they match in their canonical form,
however they are written.

**`audit:read` is not implied by any write scope.** The implication rule exists
so that a token that may change a thing can see *that thing*. The audit trail is
not that thing: it is the record of everyone who touched it. Granting
`users:write` to a provisioning script should not hand it every person's
authentication history.

**A restricted token reads only the events about its own objects.** Take a token
named to particular clients or groups that also holds `audit:read`. It sees an
event when the event's client, or the group in its detail, is one the token may
act on. An event about neither, such as a person's sign-in, is not shown to it.
Unrestricted tokens see the whole organisation as before. A one-client token used
to read the entire organisation's trail, every other client's events included.

**`organizations:write` needs an unscoped token as well as the scope.** Holding it
on a token scoped to one organisation grants nothing. Creating an organisation is
the one write with no organisation to be scoped to. An organisation that can
provision organisations has escaped the isolation everything else enforces. It
could create a sibling, and then act on it with a token for the new organisation.
Issue the scope only to a provisioning system, and separately from the scopes that
administer the people inside an organisation.

A missing scope is **403 with the scope named**, not a bare "forbidden". This is
an administrator-facing API, and an opaque refusal turns a one-line fix into an
afternoon. The answer names the scope the token lacks:

```json
{"error":"insufficient_scope","detail":"this token does not hold users:write"}
```

`*` exists but **cannot be granted to a stored token**. A saved credential that can
do everything is the thing scopes exist to replace. It belongs only to the
break-glass path below.

## The organisation boundary

A token created with `-org` may act on that organisation and no other. This is the
reason the column exists. It is enforced at **both** points an organisation gets
decided:

- the request body, on a create;
- the existing row, on an update, inside the same transaction that would modify it.

Enforcing it in only one leaves a boundary that holds for new records and not for
edits. That is worse than none, because it reads as enforced. `patchClient` had no
organisation lookup at all before this. It changed a client without ever reading
which organisation owned it, so one was added.

This was proved through the real handlers, not only through the helper:

```
create in its own org        -> allowed
create in another org        -> 403
edit another org's user      -> 403
edit another org's client    -> 403, and the client is still enabled afterwards
unscoped token               -> reaches both
```

The assertion that the client is still enabled matters. A 403 that had already
committed the change would pass a status-code check while the damage was done.

## Storage

The table holds a **SHA-256** of each token, never the token. A database backup, a
replica, or a support dump would otherwise hand over live administrative
credentials for every organisation. The secret is printed once and cannot be
recovered. If it is lost, revoke it and mint another.

SHA-256 is right here, where Argon2 is right for passwords. A token is a 256-bit
random value, not one a person chose, so there is nothing to brute force.
"Stretching", the deliberate slowness of a password hash, would only add cost to
the hottest path.

Tokens carry a `sgnadm_` prefix, so a secret scanner can spot one in a commit or a
log. Whoever finds a loose string also knows what they are holding.

## Break-glass

The environment token, `SIGNARI_ADMIN_TOKEN`, is kept as a "break-glass"
credential: the one for an emergency, when nothing else works. It still works,
still grants everything, and still needs **no database**. That is the point of
keeping it. If the database is the thing that is broken, a credential stored in it
cannot help you.

It is treated as exceptional rather than equivalent:

- every request using it is logged at `WARN`;
- `signari doctor` warns when it is the *only* way in;
- it is the only holder of `*`.

A deployment can set no environment token at all and run entirely on scoped
tokens. That is the better configuration, and it is what the live test used.

## Why authentication now reads the database

The old check was a constant-time comparison against one environment variable.
The reasoning was that a database lookup turns a guessing attempt into a query.
That was sound about load, and wrong about risk: it also meant no revocation, no
expiry, no attribution and no organisation boundary.

The lookup is one indexed probe on a SHA-256. Guessing is not the threat against a
256-bit random token. Leaking is, and leaking is what the old design had no answer
to. Revocation takes effect on the **next request**, with no restart:

```
valid token          -> 200
signari admin-token revoke -token-id ...
same token           -> 401
```

Unknown, revoked and expired tokens are answered identically. Distinguishing them
tells an attacker which of their guesses was once real.

## Attribution in the audit trail

`core.audit_events.admin_token_id` names the credential behind each change. The
trail then points at something somebody can revoke, rather than a role everybody
shares.

Adding it surfaced that **`PATCH /admin/clients/{id}` wrote no audit event at
all**. Disabling a client is the emergency lever for cutting a compromised
integration off from every person at once. There was no record of who pulled it.
There is now.

### The hash-chain trap

Each audit entry is hashed together with the one before it, so the entries form a
"chain" that shows any edit. The attribution is inside the chain hash. Attribution
the chain does not cover can be rewritten without breaking it, which leaves a
record that looks intact while naming the wrong credential.

But it is hashed **only when set**. Appending an empty string plus its separator
still changes the digest. So hashing it unconditionally invalidated every row
written before the field existed. The table is append-only and those rows cannot
be rehashed, so the entire history read as tampered. That is indistinguishable
from a real attack, which is the most useless possible failure for an integrity
mechanism.

That is not hypothetical. The first version did exactly this, and it was caught
by the existing chain-verification tests failing on rows they had always passed.
`TestExistingChainSurvivesTheAttributionField` now pins the rule by computing the
pre-field formula independently, so the trap cannot be walked back into.

## Moving the Laravel console onto a scoped token

No code change is needed. The console sends whatever is in its own
`SIGNARI_ADMIN_TOKEN`. The engine resolves an `sgnadm_` value from the database,
rather than matching its own environment variable. Create a token, and
put its value in the console's setting:

```sh
signari admin-token create -name "laravel console (prod)" -org <org-uuid> \
  -scopes users:write,clients:write,config:read -expires-in 2160h
# put the printed value in the console's SIGNARI_ADMIN_TOKEN, and unset the
# engine's own if nothing else needs break-glass
```

The console reports a refusal in words rather than a status code. The engine
names the missing scope on purpose, and burying that in a JSON dump wastes it:

| engine answers | operator sees |
| --- | --- |
| `403 insufficient_scope` | "this token does not hold users:write" |
| `403 outside_token_organisation` | "this token may only act on organisation …" |
| `403 outside_token_objects` | "this token is restricted to named clients and … is not one of them", or groups, or attributes. Until November 2026 these went out as `outside_token_organisation`, with "outside this token's organisation" in front |
| `401` | "…may have been revoked or expired — run `signari admin-token list`" |

## Signing in to the console through Signari

The console can sign its administrators in through Signari itself. Each then acts
with their own [administrative role](admin-api.md#administrative-roles), instead of
a token every administrator shares. Once it is configured, a password admits only
the break-glass account.

Set it up with the engine's CLI and the console's environment:

```sh
# the console's own client, designated for the Admin API
signari client create -org <org-uuid> -client-id console -name Console \
  -redirect https://console.example.com/signari/callback
signari client set-grants -client-id console -grant-types authorization_code,refresh_token
signari client set-admin-api -client-id console
# the people who administer, and what each may do
signari role grant -org <org-uuid> -email owner@example.com -role org-owner
# the account that works when Signari is down
php artisan signari:operator-create glass@example.com --break-glass
```

The console reads these settings:

| console setting | |
|---|---|
| `SIGNARI_ISSUER` | The issuer operators sign in at, as its discovery document names it |
| `SIGNARI_CONSOLE_CLIENT_ID`, `SIGNARI_CONSOLE_CLIENT_SECRET` | The console's client. Both unset, the console signs in with its local accounts as before |
| `SIGNARI_CONSOLE_REDIRECT_URI` | Where Signari returns to; `<console>/signari/callback` unless set |

The sign-in is the authorization code flow with Proof Key for Code Exchange
([PKCE](glossary.md#pkce)). It asks for a second factor (`acr_values=2`) and for
the Admin API's audience (`resource=<issuer>/admin`).

The console then asks the engine who signed in (`GET /admin/me`), rather than
reading a token itself. It makes the administrator's console account from the
answer, found by their ID in Signari and never by address.

It asks again on **every** console request, Livewire's included. Each time, the
engine reads the session, the person, the client's designation and the roles. So
revoking the person's session in Signari, deactivating them or taking their role
away signs them out of the console on their next click. The console's
organisation is the one the engine names. If Signari is unreachable, the request
is refused rather than served on a sign-in nothing can confirm.

What they see follows their roles, as the engine names them on that request. A
screen needs the read scope for what it shows: `users:read` for people,
`clients:read` for applications, `groups:read`, `tokens:read`, and `config:read`
for the configuration screens. A person who holds no role is not an administrator
at all.

The console reads its screens from the database views under its own role, so
this is what keeps an `app-manager` out of the people screen. Every write is the
engine's to refuse besides. A `user-manager` delegated over a group sees that
group's members on the people screen, and nobody else. The Admin API holds what
they change to the group.

An administrator signed in this way is not asked to enrol a console time-based
one-time password ([TOTP](glossary.md#totp)) as well. Signari required the second
factor, and the engine refuses their token unless the session proved one.

The break-glass account signs in with its password and the console's own second
factor, and writes with the console's `SIGNARI_ADMIN_TOKEN`. Every change it makes
is recorded as break-glass. A local account made before Signari sign-in was
configured is refused the panel (403). Give the person a role, and they sign in
through Signari instead.
