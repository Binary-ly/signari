# The Admin API

The engine's write surface. The console has no privilege on schema `core` at all
([ADR-004]), so this is the only path that exists for changing anything, and it
listens on its own address (`SIGNARI_ADMIN_ADDR`) so it can be bound to a private
interface.

Credentials and scopes are in [admin-tokens.md](admin-tokens.md).

## Conditional writes

**Every mutation accepts an `If-Match` precondition, and every response carries an
`ETag`.** This is the part worth reading even if you skim the rest.

The problem it solves is ordinary and silent. Two administrators open the same
client. The first disables it. The second, working from a page rendered before
that, saves an unrelated change — and the client is enabled again. Nobody is
told; the audit trail records two successful updates, because both were.

```sh
# read, and keep the tag
curl -s -D- https://admin.internal/admin/clients/wiki \
     -H 'Authorization: Bearer $TOKEN' | grep -i '^etag'
# ETag: "417"

# write only if nothing has changed since
curl -X PATCH https://admin.internal/admin/clients/wiki \
     -H 'Authorization: Bearer $TOKEN' \
     -H 'If-Match: "417"' \
     -d '{"enabled": false}'
```

If the configuration moved in between, the write is **refused before anything is
written** and you are told both versions:

```json
{
  "error": "precondition_failed",
  "detail": "the configuration was at version 419, not the expected 417",
  "expected_version": 417,
  "current_version": 419
}
```

Three properties are worth stating because each is a decision:

- **A refused precondition writes nothing.** The check runs inside the
  transaction, holding a row lock, before the handler's work. A 412 that arrived
  after the change had committed would be worse than no precondition at all.
- **A malformed `If-Match` is refused, not ignored.** `If-Match: 42` — unquoted,
  which RFC 7232 does not permit — gets a 400. Ignoring it would perform an
  unconditional write for a caller who asked for a conditional one, which is the
  failure mode this feature exists to remove.
- **Omitting `If-Match` is unconditional**, exactly as before. Preconditions are
  available, not mandatory; a mandatory one would break every existing caller and
  be worked around by the first person in a hurry.

`If-Match: *` means "if any configuration exists", per RFC 7232 §3.1.

### Why the version is global rather than per-resource

`core.config_version` is a single monotonic counter that every mutation bumps in
the same transaction ([ADR-008]). That is what engine nodes poll to decide when
to reload, so it already exists, is already transactional, and already identifies
the exact configuration state.

The cost is that an unrelated change elsewhere invalidates your tag, so a
conditional write can be refused when nothing touched *your* object. The
benefit is that the guarantee needs no new bookkeeping and cannot drift from the
reload signal. For an administrative API — low-volume and bursty — a retry after
re-reading is the right trade. If per-resource versions are ever wanted, this
counter stays the reload signal and the per-resource one is added beside it.

## Endpoints

Every mutation returns `config_version` in its body and `ETag` in its headers.

### Configuration

| | |
|---|---|
| `GET /admin/config-version` | The current version. The read half of the conditional-write protocol |
| `GET /admin/openapi.json` | An OpenAPI 3.1 description of this API, **generated from the router**. Unauthenticated |

**The OpenAPI document is derived, not written.** It cannot describe a route that
is not registered or omit one that is, and each operation carries the scope the
server actually enforces — taken from the same `auth(scope, …)` wrapper that
enforces it, so a generated client is a client of the server that exists rather
than of the server somebody last remembered to document. Request and response
*schemas* are not derived: reflecting over the Go structs would describe the JSON
tags rather than the meaning, so those stay in this page.

It needs no token. It describes the shape of the API and no data — the same facts
you are reading here — and requiring a token to read the description of how to
use a token costs an integrator an hour and an attacker nothing.

### Organisations

| | |
|---|---|
| `POST /admin/organizations` | Provision a tenant. `slug`, `display_name`, and `instance_id` — the last required only when the deployment has more than one instance. Needs `organizations:write` **and an unscoped token** |

**Only an unscoped token may create an organisation.** A token scoped to one
organisation is refused, because a tenant that can provision tenants has escaped
the isolation the rest of the product enforces: it could create a sibling and
then act on it. This reuses the same `MayActOn` check every other write uses
rather than adding a second boundary that has to be kept in step.

**There is no `DELETE`,** and that is a decision. Every user, client, session,
token and audit event in a deployment hangs off an organisation, so a one-call
tenant deletion is irreversible destruction of everything a customer has,
reachable by one mistyped identifier. Setting `status` to `suspended` stops the
tenant working; removing the data is a deliberate operation done with the
database in front of you.

### Clients

| | |
|---|---|
| `GET /admin/clients` | List, paged. `?limit=` (max 200) and `?cursor=` |
| `GET /admin/clients/{clientID}` | One client |
| `POST /admin/clients` | Register a client |
| `PATCH /admin/clients/{clientID}` | Enable or disable |
| `DELETE /admin/clients/{clientID}` | Remove the client and everything issued under it. Real deletion, not a flag (ADR-005): every code, token, refresh family, consent, pushed request and device authorisation cascades with it. The audit trail keeps its records — `audit_events.client_id` has no foreign key, so the history of a client outlives the client. Returns how many access tokens were revoked |
| `POST /admin/clients/{clientID}/rotate-secret` | New secret, shown once. The previous one stops working immediately |

### Users

| | |
|---|---|
| `GET /admin/users` | List, paged |
| `GET /admin/users/{userID}` | One user |
| `POST /admin/users` | Create |
| `PATCH /admin/users/{userID}` | Activate, deactivate, set a password, require a change, and edit identity: `email`, `username`, `display_name`, `given_name`, `surname`. An empty string clears a field; both identifiers cannot be cleared at once (400 `no_identifier_left`), and a taken address or name is 409 `already_exists` |
| `DELETE /admin/users/{userID}` | Remove the person and everything they hold. Real deletion, not a flag (ADR-005). Their sessions are **terminated before the row goes**, so every relying party they reached receives a back-channel logout — letting the rows cascade away would destroy the list of who to notify before anyone was notified, and leave them signed in everywhere with an account that no longer exists. Returns `sessions_ended`, `notices_queued` and `tokens_revoked`. The audit trail keeps its records: `audit_events` has no foreign key to `users`, so what a person did outlives their account |

### User attributes

Operator-defined fields on a user, declared per organisation before anything can
be stored in them.

| | |
|---|---|
| `GET /admin/organizations/{orgID}/attributes` | The organisation's declarations. Needs `config:read` |
| `PUT /admin/organizations/{orgID}/attributes` | Declare or update one. Needs `organizations:write` |
| `GET /admin/users/{userID}/attributes` | One user's values. Needs `users:read` |
| `PUT /admin/users/{userID}/attributes` | Set values. Needs `users:write` |

**An attribute must be declared before it can hold anything**, and the
declaration carries the decision that matters: `personal`. A personal attribute
is stored **sealed under the subject's own key** — the same key that protects
their TOTP secret — so `POST /admin/subjects/{subjectID}/erase` destroys it at the same
instant and by the same mechanism, with no list of tables for erasure to visit.
A list is what goes stale the first time somebody adds a table, and going stale
here means telling a person their data was destroyed when it was not.

The cost is that a sealed value **cannot be searched**. So an attribute that is
genuinely not about a person — a cost centre, a licence tier — may be declared
`"personal": false` and stored in the clear, where it is queryable and where
erasure deliberately leaves it alone.

**`personal` defaults to `true` when the field is omitted.** Forgetting makes an
attribute safe and inconvenient rather than convenient and undeletable, and the
failure that direction prevents is somebody adding `national_id` in a hurry.

**It cannot be changed once declared.** Flipping it on an attribute that already
holds values would leave rows in the wrong storage — and in one direction, a
later erasure would believe it destroyed something it did not. Changing an
attribute's sensitivity means declaring a new one and migrating deliberately.

Reads report `readable: false` rather than an error when a personal value cannot
be unsealed, which happens for exactly one reason: the subject was erased.
"Destroyed on request" and "never set" are different facts, and an audit of
whether an erasure completed needs to tell them apart.

The audit trail records **which** attributes were declared or set, never their
values — writing those into an append-only table is precisely what the sealed
storage exists to avoid.

### Second factors

| | |
|---|---|
| `GET /admin/users/{userID}/factors` | What the person can authenticate with: kind, label, whether the enrolment was completed, when it was created and last used. Recovery codes are reported as a **count of unused ones**, never listed |
| `DELETE /admin/users/{userID}/factors/{kind}` | Remove a factor the user holds one of: `totp`, `email_otp`, `sms_otp`, `duo` |
| `DELETE /admin/users/{userID}/factors/{kind}/{factorID}` | Remove one of several: `webauthn`, `recovery` |

**Removing a factor ends the person's sessions**, with the reason `mfa_reset`,
and every relying party gets a back-channel logout. The deciding case is the
stolen phone: if whoever took it has already signed in, deleting the enrolment
they are no longer using does nothing about the session they are using. It is
also what keeps the `acr` honest — those sessions asserted multi-factor
authentication and the factor behind that assertion is now gone.

**Removing someone's last factor is allowed**, deliberately, because a person who
cannot produce their only factor is exactly who this rescues. It cannot downgrade
anybody: an organisation whose flow demands MFA meets an account with nothing
enrolled and refuses the sign-in with an enrolment message, rather than admitting
it as single-factor.

No secret material is returned by any of these: no TOTP secret even encrypted, no
code hash, no public key, and neither the address nor the number behind an
email or SMS factor.

### Groups

| | |
|---|---|
| `GET /admin/groups` | List, paged |
| `GET /admin/groups/{groupID}` | One group |
| `POST /admin/groups` | Create |
| `PATCH /admin/groups/{groupID}` | Rename, or change the description |
| `DELETE /admin/groups/{groupID}` | Delete, taking its memberships with it |
| `GET /admin/groups/{groupID}/members` | List members, paged |
| `PUT /admin/groups/{groupID}/members/{userID}` | Add a member |
| `DELETE /admin/groups/{groupID}/members/{userID}` | Remove a member |

**Changing an email address clears its verified mark, always, and there is no
field to opt out.** `email_verified_at` is what makes this server assert
`email_verified: true` in an ID token and from `/userinfo`. Relying parties key
accounts on a verified address precisely because an unverified one proves
nothing — so keeping the mark while the address underneath it changes would have
this server sign a statement that somebody owns an address nobody checked. That
would make `users:write` an account-takeover primitive at every downstream
application, and the takeover would happen elsewhere, using a claim signed here,
with nothing in this server's own logs looking wrong afterwards. Re-verification
is a separate flow with its own proof.

**`may_impersonate` is reported and cannot be set here.** It grants members the
ability to act as other users, so exposing it would let a `groups:write` token
grant itself impersonation by flagging a group its own operator belongs to — the
greater privilege obtained from the lesser credential. It stays a CLI operation,
where the person running it is on the host. There is a test asserting a request
body carrying it has no effect.

A membership may not cross organisations: a group decides application access, so
joining a user from another tenant is refused with 400 even when the token could
act on both.

### Sessions

| | |
|---|---|
| `GET /admin/users/{userID}/sessions` | Live sessions for a user |
| `DELETE /admin/users/{userID}/sessions` | End all of them |
| `DELETE /admin/sessions/{sid}` | End one |

Revocation goes through the engine's single termination path, so every relying
party the person reached is sent a back-channel logout. Setting `revoked_at`
directly would end the session here and leave them signed in everywhere that
matters while this API reported success; the response returns `notices_queued` so
a caller can see the notices were raised.

The listing reports the user agent and whether an address is on file, never the
address. `ip_hash` is a hash by deliberate choice, and returning it would undo
that decision from the other side.

### Audit trail

| | |
|---|---|
| `GET /admin/audit-events` | The trail, newest first. Cursor-paged. Filters: `event_type`, `subject_id`, `client_id`, `since`, `until` (RFC 3339). Needs `audit:read` |

**`audit:read` is its own scope and is not implied by `users:write`.** The trail
says when each person authenticated, from what, and what an administrator did to
them — a larger disclosure than a user list. A provisioning script that needs to
look up users should not thereby be able to read everyone's authentication
history.

**This endpoint does not verify the hash chain, and every response says so.** The
chain is over the whole table: entry *N*'s hash covers entry *N−1*. Verifying a
*page* proves nothing, because its first entry has a predecessor the page does
not contain. Verifying the entire chain to answer a fifty-row query would read
the table, so verification stays in `signari export audit` — the operation whose
output is the evidence. The response carries `"chain_verified": false` rather
than leaving that in documentation, because somebody will build a compliance
process on this call and should find out here.

The cursor is `(occurred_at, id)`, not `occurred_at` alone: a fan-out writes
several events in one transaction with identical timestamps, and paging on a
non-unique column skips rows at every page boundary.

### Subjects

| | |
|---|---|
| `POST /admin/subjects/{subjectID}/erase` | Crypto-shred. Permanent, and requires the identifier repeated in `confirm_subject_id` |

**Erasure is not deletion, and the two are deliberately separate verbs.**
`DELETE /admin/users/{userID}` removes the account; this makes the person
unidentifiable in records that outlive it. An offboarding removes the account and
keeps the trail; a lawful erasure request keeps neither the identity nor,
usually, the account. Conflating them would mean one of the two requests is
always answered wrongly.

## What reads never return

No credential material, on any read, ever: no client secret or its hash, no
password hash, no TOTP secret, no recovery codes. A read scope must not be a
slower route to the power a write scope has, and the way that rule normally
breaks is somebody selecting `*` for convenience. There are tests asserting the
absence.

## Paging

Lists are cursor-paged on the identifier, never `OFFSET`. Offset paging re-scans
what it skips and drifts when rows are inserted mid-run, so an operator paging
through users during a provisioning run would see some twice and miss others.

`limit` is clamped to 200 whatever is asked for. An unbounded administrative list
is a memory amplifier in both the server and the client, and `?limit=100000` is
what somebody types when a page looks short.

## The organisation boundary applies to reads

A token scoped to one organisation cannot read another's, and the restriction is
in the `WHERE` clause rather than applied to the result — a filter applied
afterwards is one a later refactor moves or drops, and the failure is one tenant
enumerating another's users while the endpoint returns a cheerful 200.

[ADR-004]: the console reads through versioned views and writes only here.
[ADR-008]: every mutation bumps the configuration version in the same transaction.
