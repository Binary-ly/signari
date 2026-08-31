# Admin API access

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

One token, in an environment variable, granting everything, in every
organisation, forever. Three separate problems, and the third is the one that
matters:

| | |
| --- | --- |
| **revocation** | changing it meant restarting every node, so in practice nobody rotated it and a leaked token stayed valid indefinitely |
| **attribution** | every change in the audit trail was attributed to "the admin token", which is the same as no attribution |
| **blast radius** | the console needs to write users and clients; a monitoring script needs to read a version number. Both got the same unlimited credential, and either one leaking lost every tenant |

## Scopes

Deliberately few. A permission model nobody can hold in their head gets granted
wholesale, which is exactly the situation being replaced.

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
| `organizations:write` | `POST /admin/organizations`. Useless to an organisation-scoped token — see below |
| `audit:read` | `GET /admin/audit-events`. **Not implied by any write scope** — see below |

**A write scope implies the matching read scope.** `clients:write` can read a
client without also being granted `clients:read` — a token that may change a
thing can obviously see it, and requiring both would have silently removed access
from every token already issued the day read endpoints appeared. The implication
runs one way only: a read scope never grants a write.

**Groups get their own pair rather than riding on `users:*`.** A group decides
which applications its members reach, so granting the ability to edit membership
is granting application access — a different decision from being able to reset a
password.

**`subjects:erase` is separate from `users:write`** because a token that may
rename a user should not thereby be able to destroy one irreversibly.

## Narrowing a token to named objects

A token may be restricted to particular clients or groups, not just to a scope
and an organisation. A CI job that deploys one application should not hold a
credential able to disable the payroll system.

| | |
|---|---|
| `client_ids` | Clients this token may act on, for reads and writes alike |
| `group_ids` | Groups it may act on, including their membership |

**Unset means every object**, which is what every token issued before this
existed carries — the restriction is opt-in, for the same reason `If-Match` is.

**An empty list means *none*, not everything.** The two are deliberately
different: a `[]` that read as unrestricted is how a narrowing feature becomes a
widening one, the first time somebody clears a list intending to revoke access
and grants all of it instead.

Reads are narrowed as well as writes. A read boundary that does not match the
write boundary is one an integrator will find and use.

**`audit:read` is not implied by any write scope.** The implication rule exists
so a token that may change a thing can see *that thing*; the audit trail is not
that thing, it is the record of everyone who touched it. Granting `users:write`
to a provisioning script should not hand it every person's authentication
history.

**`organizations:write` needs an unscoped token as well as the scope.** Holding
it on a token scoped to one organisation grants nothing: creating a tenant is the
one write with no tenant to be scoped to, and a tenant that can provision tenants
has escaped the isolation everything else enforces — it could create a sibling
and then act on it with a token for the new organisation. Issue it only to a
provisioning system, and separately from the scopes that administer the people
inside a tenant.

A missing scope is **403 with the scope named**, not a bare "forbidden". This is
an operator-facing API; an opaque refusal turns a one-line fix into an afternoon.

```json
{"error":"insufficient_scope","detail":"this token does not hold users:write"}
```

`*` exists but **cannot be granted to a stored token** — a saved credential that
can do everything is the thing scopes exist to replace. It belongs only to the
break-glass path below.

## The organisation boundary

A token created with `-org` may act on that organisation and no other. This is
the reason the column exists, and it is enforced at **both** points an
organisation gets decided:

- the request body, on a create
- the existing row, on an update — inside the same transaction that would modify it

Enforcing it in only one leaves a boundary that holds for new records and not for
edits, which is worse than none because it reads as enforced. `patchClient` had no
organisation lookup at all before this — it changed a client without ever reading
which tenant owned it — so one was added.

Proved through the real handlers, not just the helper:

```
create in its own org        -> allowed
create in another org        -> 403
edit another org's user      -> 403
edit another org's client    -> 403, and the client is still enabled afterwards
unscoped token               -> reaches both
```

That last assertion matters: a 403 that had already committed the change would
pass a status-code check while the damage was done.

## Storage

The table holds a **SHA-256**, never the token. A database backup, a replica, or
a support dump would otherwise hand over live administrative credentials for
every tenant. The secret is printed once and cannot be recovered — if it is lost,
revoke it and mint another.

SHA-256 is right here where Argon2 is right for passwords: this is a 256-bit
random value, not a human-chosen one, so there is nothing to brute force and
stretching would only add cost to the hottest path.

Tokens carry a `sgnadm_` prefix so a secret scanner can spot one in a commit or a
log, and so whoever finds a loose string knows what they are holding.

## Break-glass

`SIGNARI_ADMIN_TOKEN` still works, still grants everything, and still needs **no
database**. That is the point of keeping it: if the database is the thing that is
broken, a credential stored in it cannot help you.

It is treated as exceptional rather than equivalent:

- every request using it is logged at `WARN`
- `signari doctor` warns when it is the *only* way in
- it is the only holder of `*`

A deployment can set no environment token at all and run entirely on scoped
tokens. That is the better configuration, and it is what the live test used.

## Why authentication now reads the database

The old check was a constant-time comparison against one environment variable,
on the reasoning that a database lookup turns a guessing attempt into a query.
Sound about load, wrong about risk: it also meant no revocation, no expiry, no
attribution and no organisation boundary.

The lookup is one indexed probe on a SHA-256. Guessing is not the threat against
a 256-bit random token — leaking is, and leaking is what the old design had no
answer to. Revocation takes effect on the **next request**, with no restart:

```
valid token          -> 200
signari admin-token revoke -token-id ...
same token           -> 401
```

Unknown, revoked and expired tokens are answered identically. Distinguishing them
tells an attacker which of their guesses was once real.

## Attribution in the audit trail

`core.audit_events.admin_token_id` names the credential behind each change, so
the trail points at something somebody can revoke rather than a role everybody
shares. Adding it surfaced that **`PATCH /admin/clients/{id}` wrote no audit
event at all** — disabling a client is the emergency lever for cutting a
compromised integration off from every user at once, and there was no record of
who pulled it. There is now.

### The hash-chain trap

The attribution is inside the chain hash: attribution the chain does not cover
can be rewritten without breaking it, leaving a record that looks intact while
naming the wrong credential.

But it is hashed **only when set**. Appending an empty string plus its separator
still changes the digest, so hashing it unconditionally invalidated every row
written before the field existed. The table is append-only and those rows cannot
be rehashed, so the entire history read as tampered — indistinguishable from a
real attack, which is the most useless possible failure for an integrity
mechanism.

That is not hypothetical: the first version did exactly this, and it was caught
by the existing chain-verification tests failing on rows they had always passed.
`TestExistingChainSurvivesTheAttributionField` now pins the rule by computing the
pre-field formula independently, so the trap cannot be walked back into.


## Moving the Laravel console onto a scoped token

No code change is needed. The console sends whatever is in its own
`SIGNARI_ADMIN_TOKEN`, and the engine resolves an `sgnadm_` value from the
database rather than matching its own environment variable:

```sh
signari admin-token create -name "laravel console (prod)" -org <org-uuid> \
  -scopes users:write,clients:write,config:read -expires-in 2160h
# put the printed value in the console's SIGNARI_ADMIN_TOKEN, and unset the
# engine's own if nothing else needs break-glass
```

The console reports a refusal in words rather than a status code — the engine
names the missing scope on purpose, and burying that in a JSON dump wastes it:

| engine answers | operator sees |
| --- | --- |
| `403 insufficient_scope` | "this token does not hold users:write" |
| `403 outside_token_organisation` | "this token may only act on organisation …" |
| `401` | "…may have been revoked or expired — run `signari admin-token list`" |
