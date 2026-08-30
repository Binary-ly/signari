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
| `PATCH /admin/users/{userID}` | Activate, deactivate, set a password, require a change |

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

### Subjects

| | |
|---|---|
| `POST /admin/subjects/{subjectID}/erase` | Crypto-shred. Permanent, and requires the identifier repeated in `confirm_subject_id` |

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
