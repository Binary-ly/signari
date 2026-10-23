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

The console sends the version each page was rendered from, read before the rows
it shows, with every write it makes, creates included. A confirmation opened
before somebody else's change is refused with nothing written, and the page
then shows the change and carries its version, so trying again works. Until
October 2026 it read the version just before each write. That caught only two
saves in the same moment, so the scenario above still happened through the
console.

### Why the version is global rather than per-resource

`core.config_version` is a single monotonic counter that every mutation bumps in
the same transaction ([ADR-008]). So it already exists, is already
transactional, and already identifies the exact configuration state. Nothing
polls it: configuration is read per request, and the few caches refresh on
their own timers.

"Every mutation" includes the command line. An operator's `signari` command
moves the version in its own transaction, because a trigger on every `core`
table bumps it for a session the CLI has marked as itself. Request-path and
background writes do not carry the mark and move nothing. Until October 2026
only three CLI commands moved it, so a conditional write read before
`client disable` applied over it and put the client back.

The cost is that an unrelated change elsewhere invalidates your tag, so a
conditional write can be refused when nothing touched *your* object. The
benefit is that the guarantee needs no new bookkeeping and cannot drift from the
reload signal. For an administrative API — low-volume and bursty — a retry after
re-reading is the right trade. If per-resource versions are ever wanted, this
counter stays the reload signal and the per-resource one is added beside it.

## Who made a change

Every audit record a request writes names the admin token that made it in
`admin_token_id`. A request made with the break-glass environment token, which
has no row to name, is marked `break_glass: true` in its detail. A caller acting
for a person can say which with `Signari-Operator`, and every record of the
request carries it as `detail.operator`:

```sh
curl -X PATCH https://admin.internal/admin/clients/wiki \
     -H 'Authorization: Bearer $TOKEN' -H 'Signari-Operator: console-user:42' \
     -H 'If-Match: "417"' -d '{"enabled": false}'
```

The console sends its signed-in user's reference this way, so two people using
one console token are two operators in the trail. The value is the caller's own
reference, 1 to 128 of `A-Z a-z 0-9 . _ : -`, asserted by the token's holder
and not checked here: the token is the authenticated party. An address is
refused (no `@`), because the trail is append-only and nothing erases it. A
client update records each setting it changed with what it was and what it
became; a person's fields are named, never recorded.

## Endpoints

Every mutation returns `config_version` in its body and `ETag` in its headers.

An id in a path (`{userID}`, `{groupID}`, `{subjectID}`, `{orgID}`, `{mapperID}`)
must be a uuid in its canonical form, lower case `8-4-4-4-12`, or the request is
`400 invalid_request`. PostgreSQL accepts other spellings of the same uuid, braced
or with a hyphen after every four digits, and a check that read an id more strictly
than the write it guarded once let a `users:write` token take over an administrator.
One spelling at the boundary means every check, write and audit record names the
row the same way. An `org_id` in a body is held to the same rule, and a write
naming an organisation that does not exist, in a body or a path, is
`404 organization_not_found`. A token held to one organisation is refused every
other id with `403` alike, so it cannot learn which exist.

### Configuration

| | |
|---|---|
| `GET /admin/config-version` | The current version. The read half of the conditional-write protocol |
| `GET /admin/system` | What the deployment is: the `release` and `commit` serving the API and the Go toolchain, the schema version `applied` and the one the `binary` carries, whether the binary is `fingerprint_pinned`, how many `instances`, `organizations` and suspended ones it holds, and the `rate_limits` in force. `config:read` **and an unscoped token**, since the count of tenants is not one tenant's to read |
| `GET /admin/instances` | The deployment's instances, each an issuer: `id`, `issuer`, `display_name`, `created_at`. `config:read` **and an unscoped token**, since every organisation of an instance shares it |
| `GET /admin/instances/{instanceID}/brand` | The instance's appearance on every page it renders: `branded`, `product_name`, `logo_url`, `support_url`, and the four colours `colour_primary`, `colour_on_primary`, `colour_background`, `colour_text`. `config:read` and an unscoped token |
| `PUT /admin/instances/{instanceID}/brand` | Those fields, replacing the brand as `signari brand set` does; one left out is the built-in. Refused with `400 invalid_brand` naming the field when the page would be unreadable or unsafe: a logo or support link that is not `https`, colours not all four or none, or text whose contrast is under 4.5:1. Takes effect on the next page rendered. Audited `admin.brand_set`; `organizations:write` and an unscoped token, honours `If-Match` |
| `GET /admin/organizations/{orgID}/event-subscriptions` | Where the organisation's recorded events are delivered (see [events.md](events.md)): each subscription's `id`, `name`, `url`, `event_types` (empty for every event), `enabled` and any `disabled_reason`, and how many deliveries were `delivered` and are `outstanding`. Never a secret. `config:read`; registered with a root key |
| `POST /admin/organizations/{orgID}/event-subscriptions` | `{"name": "siem", "url": "https://siem.example/hooks/signari", "event_types": ["login.failed"]}` subscribes, as `signari events subscribe` does, and answers the signing `secret` **once**: it is stored sealed and never shown again. The URL is `https` and may not reach a private address (`400 invalid_url`); an event type nothing records is `400 unknown_event_type` with the nearest one suggested; a name the organisation has is `409 already_exists`. Audited `admin.subscription_created`; `organizations:write` |
| `DELETE /admin/organizations/{orgID}/event-subscriptions/{name}` | Remove it, as `signari events remove` does: nothing more is delivered to it. `404 subscription_not_found` for a name the organisation does not have. Audited `admin.subscription_removed` |
| `POST /admin/organizations/{orgID}/event-subscriptions/{name}/rotate-secret` | A new signing secret, answered once; the old one stops verifying, including for retries already queued, as `signari events rotate` does. Audited `admin.subscription_secret_rotated` |
| `POST /admin/organizations/{orgID}/event-subscriptions/{name}/enable` | Switch it back on after ten failed deliveries switched it off, as `signari events enable` does; events recorded while it was off are not sent. Audited `admin.subscription_enabled` |
| `POST /admin/organizations/{orgID}/event-subscriptions/{name}/test` | Queue one signed `signari.test` delivery to it through the outbox, as every delivery goes, answering its `event_id`, as `signari events test` does. Audited `admin.subscription_tested` |
| `GET /admin/organizations/{orgID}/providers` | The services the organisation's hooks call (see [extensibility.md](extensibility.md)): each provider's `id`, `hook`, `url`, `mode`, `timeout_ms`, `enabled`, whether its calls are `signed`, whether any decision point consults the hook (`called`), and the `allowed_claims` a token hook may add. Never a secret. `config:read`; registered with a root key |
| `PUT /admin/organizations/{orgID}/providers/{hook}` | `{"url": "https://policy.example/decide", "mode": "fail_closed", "timeout_ms": 2000}` registers the hook's provider or replaces it, as `signari provider add` does. `mode` has no default; `timeout_ms` defaults to 2000 and may not pass 5000. An unknown hook, a missing mode, a timeout out of range or a URL that is not `https` or reaches a private address is `400 invalid_provider`. A first registration answers the signing `secret` **once**; a replacement answers it empty, because the provider keeps the one it holds. Refused `403 outside_token_objects` to a token limited to named applications or groups, since every sign-in passes through it. Audited `admin.provider_set`; `organizations:write` |
| `DELETE /admin/organizations/{orgID}/providers/{hook}` | Remove it, as `signari provider remove` does: the decision is made locally only. `404 provider_not_found` when the organisation has none for the hook. Audited `admin.provider_removed` |
| `POST /admin/organizations/{orgID}/providers/{hook}/rotate-secret` | A new signing secret, answered once; the old one stops verifying at once, as `signari provider rotate` does. Audited `admin.provider_secret_rotated` |
| `PUT /admin/organizations/{orgID}/providers/{hook}/claims` | `{"claims": ["department"]}` replaces what a token hook may add to a token, as `signari provider claims` does; an empty list lets it add nothing. A claim the protocol decides (`sub`, `iss`, `aud`, `exp` and the rest) is `400 protocol_claim`. Audited `admin.provider_claims_set` |
| `GET /admin/instances/{instanceID}/keys` | The instance's signing keys: each `kid`, `algorithm`, `state` (`next`, published and signing nothing; `active`; `passive`, published so tokens it signed still verify), `published_at`, `demoted_at`, and for a passive key `retirable_in_s`. Never a private half. `config:read` and an unscoped token; registered with a root key |
| `POST /admin/instances/{instanceID}/keys/rotate` | `{"algorithm": "", "promote_now": false}` takes the next safe step for each algorithm in use, or only the one named, as `signari keys rotate` does: publishes a `next` key where there is none, and promotes one once it has been published for a day, demoting the active one to passive. The answer's `steps` say what was done, or how long until the next key may be promoted (`wait_s`). `promote_now` promotes before the wait is over, which is right for a compromised key; relying parties whose key cache predates it reject its signatures until they refresh, and the step says `forced`. An algorithm nothing signs with is `400 cannot_rotate`: rotation does not introduce one. Waits for the unattended rotator's pass rather than racing it. Each step is audited `keys.rotated`; `organizations:write` and an unscoped token |
| `POST /admin/instances/{instanceID}/keys/retire` | Retire every passive key whose dwell is over, as `signari keys retire` does, answering the `retired` key ids; one still within its dwell, or with no demotion time recorded, stays. There is no early retirement: it would not stop a compromised key being used, which demotion did, and would break tokens already in the field |
| `GET /admin/instances/{instanceID}/federation` | Whether the instance is a federation entity (see [openid-federation.md](openid-federation.md)): its `entity_id` (its issuer), `enabled`, `authority_hints`, `trust_anchor_hints`, `organization_name`, `homepage_uri`, `contacts` and the Entity Configuration's `lifetime_s`. `config:read` and an unscoped token; registered with a root key |
| `PUT /admin/instances/{instanceID}/federation` | `{"authority_hints": ["https://anchor.example"], "organization_name": "Example University", "homepage_uri": "", "trust_anchor_hints": [...], "contacts": [...], "lifetime_s": 43200}` makes the instance a federation entity, or changes what it publishes, as `signari federation enable` does. `authority_hints` are required, since with none it would be a Trust Anchor, which this engine cannot be; a list left out is kept and an empty one clears it. A hint that is not an Entity Identifier, or a lifetime outside 5 minutes to 168 hours, is `400 invalid_federation`; an issuer that cannot be an Entity Identifier is `400 federation_refused`. The first enable generates the federation key, names it in `generated_key` and answers `restart_required`, because the Entity Configuration's route is registered when `serve` starts. Audited `admin.federation_enabled`; `organizations:write` and an unscoped token |
| `GET /admin/instances/{instanceID}/trust-marks` | What the instance `issued` as an accreditation authority (see [trust-marks.md](trust-marks.md)), each with its `type`, `subject`, `status`, `issued_at`, `expires_at`, and for a revoked one `revoked_at` and `reason`; and what it `held`, each mark's `type`, `issuer`, `added_at`, `expires_at`, and whether it is `published` (an expired one is kept and not). Never a mark's JWT. `config:read` and an unscoped token |
| `POST /admin/instances/{instanceID}/trust-marks` | `{"type": "https://federation.example/profile/privacy-v2", "subject": "https://rp.example.org", "lifetime_s": 31536000, "logo_uri": "", "ref": "", "delegation": ""}` issues a Trust Mark signed with the federation key, as `signari trust-mark issue` does, superseding an active one of the type for the subject, and answers it in `trust_mark` with its `expires_at`. `lifetime_s` 0 issues one with no `exp`, which readers can tell from a withdrawn one only by asking the status endpoint. A type that is not an absolute URL, or a subject that is not an Entity Identifier, is `400 federation_refused`; an instance with federation not enabled is `409 federation_not_enabled`. Audited `admin.trust_mark_issued`; `organizations:write` and an unscoped token |
| `POST /admin/instances/{instanceID}/trust-marks/revoke` | `{"type": "...", "subject": "...", "reason": "..."}` revokes the active one, as `signari trust-mark revoke` does; readers learn of it from the status endpoint, and the subject keeps publishing its copy. `404 trust_mark_not_found` when there is none active. Audited `admin.trust_mark_revoked` |
| `PUT /admin/instances/{instanceID}/held-trust-marks` | `{"trust_mark": "<compact JWT>"}` publishes a mark another issuer granted this entity in its Entity Configuration, as `signari trust-mark accept` does. Its signature is not checked, which is the reader's job; one issued to another entity, expired, or not a Trust Mark is `400 federation_refused`, because publishing it would make readers reject the document. Audited `admin.trust_mark_accepted` |
| `DELETE /admin/instances/{instanceID}/held-trust-marks` | `?type=...&issuer=...` stops publishing it, as `signari trust-mark drop` does. `404 trust_mark_not_found` when the entity holds none of that type from that issuer. Audited `admin.trust_mark_dropped` |
| `POST /admin/instances/{instanceID}/trust-mark-delegations` | `{"type": "...", "delegate": "https://issuer.example", "lifetime_s": 31536000, "ref": ""}` authorises another entity to issue marks of a type this one owns, as `signari trust-mark delegate` does, and answers the signed `delegation` for the delegate to present; nothing else is stored. Readers check it against the owner keys the Trust Anchor publishes. Audited `admin.trust_mark_delegated` |
| `GET /admin/instances/{instanceID}/webauthn` | The Relying Party identity the instance's passkeys are bound to: `rp_id` (empty while passkeys are unavailable), `rp_display_name`, and the `related_origins` a passkey made under it may also be used from. `config:read` and an unscoped token |
| `PUT /admin/instances/{instanceID}/webauthn` | `{"rp_id": "example.com", "rp_display_name": "Example", "related_origins": []}` sets them, as `signari instance webauthn` and `related-origins` do. The RP ID is a bare registrable domain, never an address, scheme, port or path (`400 invalid_rp_id`); each origin is an `https` origin written as a browser writes it (`400 invalid_related_origin`). Changing an RP ID already set makes every passkey registered under it unusable for good, so it is `409 rp_id_change_unconfirmed` unless `"replace_rp_id": true`, and the answer names the `replaced_rp_id`. Audited `admin.instance_webauthn_set`; `organizations:write` and an unscoped token, honours `If-Match` |
| `GET /admin/instances/{instanceID}/issuer-aliases` | Legacy issuers the instance also claims while relying parties move across: each `issuer`, its `retire_after` (null for none planned) and how many clients are `pinned_clients` to it. `config:read` and an unscoped token |
| `POST /admin/instances/{instanceID}/issuer-aliases` | `{"alias": "https://old.example.com", "retire_after": "2026-12-31T00:00:00Z"}` claims one, as `signari instance add-alias` does: accepted by userinfo, introspection and the other token checks from the next request. An `https` URL with no query, fragment or trailing slash, not an instance's own issuer nor another's alias, with any retirement in the future (`400 invalid_issuer_alias`). Audited `admin.issuer_alias_added` |
| `PATCH /admin/instances/{instanceID}/issuer-aliases` | `{"alias", "retire_after"}` retires one, now when `retire_after` is left out, as `signari instance retire-alias` does: clients pinned to it get the instance's own issuer from then on. Audited `admin.issuer_alias_retired` |
| `DELETE /admin/instances/{instanceID}/brand` | Return the instance's pages to the built-in appearance; `404 not_branded` when they show it. Audited `admin.brand_removed` |
| `GET /admin/openapi.json` | An OpenAPI 3.1 description of this API, **generated from the router**. Unauthenticated |
| `POST /admin/batch` | `{"operations": [{"method", "path", "body"}, …]}`, 1 to 100 writes (POST, PUT, PATCH, DELETE on `/admin/` or `/admin/v1/`) in **one transaction, all or none**, with one configuration bump. Each operation is checked as if sent alone, with the batch's token: its scope, organisation, objects and privileged-target rules all apply, so a batch widens nothing. The first one refused ends the batch, and nothing any of them wrote is kept. The answer is `400`/`403`/`404`/… `batch_failed` with `failed_index` and that operation's `status` and `response`. Otherwise `200` with the `config_version` committed and each operation's `status` and `body`, each reporting that version. The batch's own `If-Match` is checked once, before the first operation. An operation sees what was committed before the batch, not an earlier operation's write, so one that needs another's result (a member for a group the same batch creates) goes in a second batch. Each operation is audited as it would be alone. Needs no scope of its own |

**Versioning.** Every route is also served under `/admin/v1/`, the same route
table under both. This API is version 1. A change that breaks a caller (a field
removed or renamed, a meaning changed) would come as `/admin/v2/` beside it,
with `/admin/v1/` and `/admin/` kept as they are. Adding a route, an optional
request field or a response field is not a break, so a caller should ignore
response fields it does not know, though the documented schemas name every one
there is. Pin `/admin/v1/` to be held to that.

**The OpenAPI document is derived, not written.** It cannot describe a route that
is not registered or omit one that is, and each operation carries the scope the
server actually enforces — taken from the same `auth(scope, …)` wrapper that
enforces it, so a client generated from it calls the routes that exist, with the
scopes they need, rather than those somebody last remembered to document. Each
operation has typed schemas too. The request body's schema is taken from the type
the handler decodes, so it cannot name a field the server does not read. The
success response is declared field by field, closed to undeclared fields, and
every refusal shares one `Error` schema (`error`, `detail`, and the two versions
of a 412). A test calls every operation and holds what it answers to its schema,
an undeclared field included, so the document and the server cannot drift apart
unseen. The meaning of each field, what absent does, stays on this page. Until
October 2026 the document had no bodies at all.

Every timestamp is RFC 3339 with the offset's minutes (`2026-10-22T14:51:46.035024+02:00`).
Most read endpoints wrote `+02`, which RFC 3339 does not allow and a strict parser
refuses, and a person's factors used a space for the `T`.

It needs no token. It describes the shape of the API and no data — the same facts
you are reading here — and requiring a token to read the description of how to
use a token costs an integrator an hour and an attacker nothing.

### Admin tokens

| | |
|---|---|
| `GET /admin/tokens` | Every admin token for an unscoped caller, its organisation's for a scoped one: name, scopes, organisation, narrowing, and when it was made, expires, was revoked and was last used. Never a secret or a hash. `tokens:read` |
| `POST /admin/tokens` | `{"name", "scopes", "org_id", "client_ids", "group_ids", "expires_in_s"}`. Refused 403 `wider_than_caller`, naming the dimension, unless every scope is the caller's, the organisation is the caller's, the clients and groups are among the caller's, and it expires no later than the caller. Expires in ninety days unless asked, at most a year. The answer carries the `secret`, once. Audited `admin.token_created`; `tokens:write`; honours `If-Match` |
| `POST /admin/tokens/{tokenID}/rotate` | `{"grace_s", "expires_in_s"}`, both optional: a replacement with the same terms, its `secret` returned once, the old one working until `replaced_works_until` (a day unless asked, at most a week, 0 for at once). Only a token no wider than the caller, or the caller itself, since the rotator holds the new secret. Audited `admin.token_rotated`; `tokens:write`; honours `If-Match` |
| `DELETE /admin/tokens/{tokenID}` | Revoke, at once. Only a token no wider than the caller, or itself. Audited `admin.token_revoked`; `tokens:write`; honours `If-Match` |

See [admin-tokens.md](admin-tokens.md) for the rule and why rotation is held to it.

### Administrative roles

A role is a named set of the scopes above, given to a person or an application
in one organisation by a **binding**. It grants nothing a token could not be
given, so every check on this page applies to it unchanged.

| Role | Scopes |
|---|---|
| `org-owner` | Every scope a stored token may hold, in the organisation: `users:write`, `clients:write`, `groups:write`, `config:read`, `subjects:erase`, `subjects:export`, `organizations:write`, `audit:read`, `privileged-users:write`, `tokens:write`. Not creating or suspending organisations, which stay with an unscoped token |
| `user-manager` | `users:write`: accounts, factors, sessions, consents, attributes and invitations. Not groups, which decide what applications a person reaches |
| `app-manager` | `clients:write` and `config:read` |
| `auditor` | Every read scope and `audit:read` |

A `user-manager` binding may name a group, and then reaches only that group's
members (delegated administration): every route on a person answers
`403 outside_token_organisation` for anyone else, existing or not, the user list
and the invitation list show its groups' members and invitations only, and ending
a session by its id is refused for a non-member's. It adds people by invitation
into its own groups, naming at least one, since a person created outright would
be outside its reach the moment they existed; `POST /admin/users` is refused it.
It cannot change group membership, which is `groups:write`. A role is read on each of its holder's
requests, never carried in a credential, so a binding removed refuses the next
one. A person who holds any role is a privileged target, like a member of a group
that may impersonate: writing on them needs `privileged-users:write`, so a user
manager cannot reset an owner's password and become one.

| | |
|---|---|
| `GET /admin/organizations/{orgID}/role-bindings` | Each binding: its `id`, `role`, `user_id` or `client_id`, any `group_id`, and when it was made. `config:read` |
| `POST /admin/organizations/{orgID}/role-bindings` | `{"role", "user_id" or "client_id", "group_id"}`. The holder and the group must be in the organisation (404 otherwise, the same for one that does not exist). Refused 403 `wider_than_caller` unless the caller holds every scope of the role over everything it reaches. Audited `admin.role_granted`; `organizations:write`; honours `If-Match` |
| `DELETE /admin/organizations/{orgID}/role-bindings/{bindingID}` | Take one away, held to the same rule, so a narrow credential cannot remove an owner. Audited `admin.role_revoked`; `organizations:write`; honours `If-Match` |
| `GET /admin/me` | Who the caller is, as this request was authenticated: `kind` (`person`, `application`, `token` or `break_glass`), `name`, `org_id` (null for a deployment-wide caller), `scopes`, `delegated` (each scope a delegated role narrows, with its groups), `expires_at`, and for a person their `user` (`id`, `email`, `display_name`). Any authenticated caller, no scope of its own. The console asks it on each of its requests, and a `401` is how it learns a person's session or role has ended |

`signari role grant` makes the first owner, before anybody can grant one here.

**Acting with a role.** A role is used with one of this deployment's own access
tokens, presented as the bearer in place of an admin token. It must be audienced
`<issuer>/admin` (the issuer with `/admin`, an identifier rather than an address)
and issued to a client designated for the Admin API (`admin_api`, or
`signari client set-admin-api`), which asks for it as the RFC 8707 `resource`,
alone:

- **A person** signs in to such a client (the console) with the authorization
  code flow and `resource=<issuer>/admin`, and acts with the roles they hold.
  Their session must have proved a second factor, or the request is
  `403 multi_factor_required`.
- **An application** acting as itself uses `client_credentials` with the same
  `resource`, and acts with the roles bound to its client id.

On every request the token's signature, issuer, audience and expiry are checked,
and then whether it, its grant, its session, its client and its holder are still
live, whether the client is still designated, and which roles the holder has
now. A token never carries what it may do, so taking a role away, ending the
session or withdrawing the designation refuses the next request. A
sender-constrained (DPoP or certificate-bound) token is refused, since this API
does not check proofs, and so is one signed under a legacy issuer alias. The
audit record of what a role holder changes names the person as its `actor_id`
and the holder as `detail.admin_principal` (`user:<id>` or `client:<id>`). An
owner minting an admin token this way is held to the rule every minter is: the
new token may not outlive the caller, here the access token presented, so a
stolen one cannot be turned into a credential that outlasts it. An automation's
long-lived token is made with `signari admin-token create` or a deployment-wide
token.
No organisation may register `<issuer>/admin` as a resource server of its own.

### Organisations

| | |
|---|---|
| `POST /admin/organizations` | Provision a tenant. `slug`, `display_name`, and `instance_id` — the last required only when the deployment has more than one instance. Needs `organizations:write` **and an unscoped token** |
| `GET /admin/organizations` | Every organisation, with its `status`, for an unscoped token; its own for a scoped one. `config:read` |
| `GET /admin/organizations/{orgID}` | One organisation and its `status`. `config:read` |
| `PATCH /admin/organizations/{orgID}` | `{"status": "suspended"}` or `"active"`. Suspended, the organisation is refused at every entry point from the next request: sign-in by any method, the sessions it has, its clients at every OAuth and OIDC endpoint, its tokens at userinfo and introspection, LDAP binds, RADIUS, SCIM provisioning, its outposts (AuthZEN and LDAP), sign-up, recovery and passkey links, and its own admin tokens, which get 403 `organisation_suspended`. **Nothing is ended**: reactivated, a session or grant with time left resumes, so end them as well if that is what you mean. Audited `admin.organization_suspended` / `admin.organization_reactivated`. Needs `organizations:write` **and an unscoped token**, since a tenant that could lift its own suspension would not be suspended; honours `If-Match`. `signari instance org-status` does the same |
| `GET /admin/organizations/{orgID}/budgets` | The organisation's budgets in force: `tokens_per_minute` (what its clients may be issued at the token endpoint) and `sign_ins_per_minute` (what its sign-in pages may take), each with whether it is the deployment's default (6000 and 1200). `config:read` |
| `PUT /admin/organizations/{orgID}/budgets` | `{"tokens_per_minute", "sign_ins_per_minute"}`, each 1 to 1000000, left out or `null` for the default. Counted for the organisation alone, in one window shared by every instance, so one tenant's batch job or sign-in rush spends its own budget and leaves every other's whole; past it, its token requests get `429 temporarily_unavailable` and its sign-in page `429`, each with `Retry-After`. Charged at the token endpoint once the client has authenticated, and at sign-in before any password is hashed. Audited `admin.organization_budgets_set`. Needs `organizations:write` **and an unscoped token**, since a tenant that set its own budget would have none; honours `If-Match`. `signari instance org-budgets` does the same |
| `GET /admin/organizations/{orgID}/settings` | The organisation's sign-in and session policy: `max_concurrent_sessions` (0 for none) and `session_limit_behaviour` (`deny` or `evict_oldest`), `password_only_binds` (`allow` or `refuse_when_mfa`), `remember_device_days`, `new_device_notice`, `reauth_window_s`, `session_lifetime_s`, `session_idle_s` (0 when an unused session is not ended early), `offline_lifetime_s`, `persistent_sessions`, `sms_numbers` (`stored` or `hashed`), `totp_algorithm`, `totp_digits` and `totp_period_s`, `login_free_attempts` and `login_max_delay_s`. `config:read` |
| `PATCH /admin/organizations/{orgID}/settings` | Any of those fields; the rest are left as they are. Each is set as its `signari instance` command sets it (`session-limit`, `password-binds`, `remember-device`, `new-device-notice`, `reauth-window`, `session-lifetime`, `sms-numbers`, `totp-policy`, `login-throttle`), with the same bounds, and the four session fields are applied together as `session-lifetime` applies them, so a shorter lifetime shortens the sessions already signed in. One value out of bounds is `400 invalid_setting` naming the bound, and nothing in the request is changed. Each change is audited with its command's event (`org.session_limit_set`, `org.password_only_binds_set` and so on) and `via: admin_api`. Answers the settings as they now are; `organizations:write`, honours `If-Match` |
| `GET /admin/organizations/{orgID}/signup` | Whether people may make their own accounts: `enabled`, the `allowed_domains` an address must be at (or `any_domain`), the `default_groups` a new account joins, `require_verified_email` (it proves its address with a code before its first sign-in) and `require_approval` (it waits, pending, until an administrator activates it). Off reads `enabled: false`. `config:read` |
| `PUT /admin/organizations/{orgID}/signup` | `{"allowed_domains": ["example.com"], "default_groups": [], "require_verified_email": true, "require_approval": false}` opens self-sign-up or replaces its rule, as `signari signup enable` does. An empty domain list is `400 invalid_rule` unless `"any_domain": true` asks for every address by name, and naming both is refused too. `require_verified_email` is true unless set false. A default group the organisation lacks, or one a token narrowed to some groups may not act on, is `400 unknown_group`. Audited `admin.signup_rule_set`; `organizations:write`, honours `If-Match` |
| `GET /admin/organizations/{orgID}/duo` | The organisation's Duo application: whether it is `configured` and `enabled`, its `client_id` (integration key) and `api_host`, whether it `fail_open`s, and how many people are `enrolled`. Never the secret. `config:read`; registered with a root key, as the attribute routes are |
| `PUT /admin/organizations/{orgID}/duo` | `{"client_id", "secret", "api_host", "fail_open": false}` configures it, as `signari duo set` does. The integration key is 20 characters, the secret 40, and the host a `duosecurity.com` or `duofederal.com` name (`400 invalid_duo`); then the keys are checked against Duo, and one it refuses or cannot be reached for is `400 duo_check_failed` with nothing stored. The secret is sealed with the root key. `fail_open` lets people sign in without the second factor while Duo is unreachable, so whoever can stop one person's traffic to Duo removes it. Register `<issuer>/login/duo/callback` with Duo. Audited `admin.duo_set`; `organizations:write`, honours `If-Match` |
| `PUT /admin/users/{userID}/duo` | `{"duo_username": "ada"}` enrols the person by the username they have **in Duo**, which Duo returns and the sign-in is checked against and is often not their address, as `signari duo enroll` does; their next sign-in asks for a Duo prompt after the password. `409 duo_not_configured` when the organisation has no working Duo application. Removing it is `DELETE /admin/users/{userID}/factors/{kind}` with the kind `duo`. Audited `admin.duo_enrolled`; `users:write` |
| `GET /admin/organizations/{orgID}/uma` | UMA resource-owner intervention: `owner_intervention` (a refused request from an identified requesting party waits for a decision, and its client is told `request_submitted`; off, it is `request_denied`) and `poll_interval_s`. `config:read` |
| `PUT /admin/organizations/{orgID}/uma` | `{"owner_intervention": true, "poll_interval_s": 30}` sets both, as `signari uma settings` does; the interval is 5 to 3600 seconds (`400 invalid_poll_interval`), 0 for 30. Audited `admin.uma_settings_set`; `organizations:write`, honours `If-Match` |
| `GET /admin/organizations/{orgID}/uma/requests` | The requests waiting for a decision: each `id`, the `client_id` and `resource_server`, the `requesting_party`, the `permissions` it asks for, and the `relations` that, granted, would let the whole of it through. `config:read` |
| `POST /admin/organizations/{orgID}/uma/requests/{requestID}/approve` | `{"relation": "viewer"}` grants the relation to the requesting party on every resource the request names, in the authorization model, and approves it, together, as `signari uma approve` does; the client's next poll passes. A relation that would not satisfy every scope asked for is `400 relation_does_not_satisfy` with the `relations` that would, an organisation with no model is `409 no_authorization_model`, and a request already decided is `409 already_decided`. The decision names the person when the token is one's own. Audited `admin.uma_request_approved`; `organizations:write` |
| `POST /admin/organizations/{orgID}/uma/requests/{requestID}/deny` | Close the request, granting nothing; the client learns it on its next poll, as `request_denied`. Audited `admin.uma_request_denied` |
| `GET /admin/organizations/{orgID}/attesters` | The Trusted Client Attesters whose client attestations the organisation accepts: each `name`, how many `keys`, its `description` and when it was `created_at`. Never the keys. `config:read` |
| `PUT /admin/organizations/{orgID}/attesters/{name}` | `{"jwks": {"keys": […]}, "description"}` trusts the attester's public key set, or replaces it, as `signari attester add` does; a description left out keeps the one it had. A set that does not parse, holds no keys or an unusable one, or holds a **private** key (which would let this server forge the attestations it verifies) is `400 invalid_attester`. Audited `admin.attester_set`; `organizations:write`, honours `If-Match` |
| `DELETE /admin/organizations/{orgID}/attesters/{name}` | Stop trusting it: an attestation it signed is refused from the next request. `404 attester_not_found` for none of that name. Audited `admin.attester_removed` |
| `GET /admin/organizations/{orgID}/credential-configurations` | The credentials the organisation issues over OID4VCI (see [oid4vci.md](oid4vci.md)): each one's `id` (the `credential_configuration_id` a wallet asks for), `format`, `vct`, the claims `always` visible and those `selective`ly disclosed, its `lifetime_s` (0 for no `exp`), `display_name`, and whether it issues only to an attested key. `config:read` |
| `PUT /admin/organizations/{orgID}/credential-configurations/{configID}` | `{"vct": "https://example.com/identity_credential", "always": ["email"], "selective": ["preferred_username"], "lifetime_s": 31536000, "display_name": "Staff ID", "require_key_attestation": true}` defines the credential or redefines it, as `signari credential define` does; `require_key_attestation` left out keeps what was set. Claims come from `sub`, `email`, `email_verified` and `preferred_username` only, since every one ends up in something the holder shows to anybody. No claims, no `vct`, a claim off that list or in both lists is `400 invalid_credential`. Refused `403 outside_token_objects` to a token limited to named applications or groups. Audited `admin.credential_defined`; `organizations:write` |
| `GET /admin/organizations/{orgID}/credential-proof-roots` | The CAs an `x5c` key proof's chain may verify to: each `name`, the certificate's `subject` and `not_after`. No roots means every `x5c` proof is refused. `config:read` |
| `PUT /admin/organizations/{orgID}/credential-proof-roots/{name}` | `{"certificate": "<PEM>"}` trusts the CA, or replaces the one of that name, as `signari credential trust-root` does. One certificate, a CA's, unexpired, and no private key with it, or `400 invalid_root`. Refused `403 outside_token_objects` to a token limited to named applications or groups. Audited `admin.credential_root_trusted` |
| `DELETE /admin/organizations/{orgID}/credential-proof-roots/{name}` | Stop trusting it, as `signari credential untrust-root` does: chains to it are refused from the next credential request. `404 root_not_found`. Audited `admin.credential_root_untrusted` |
| `GET /admin/organizations/{orgID}/authorization-detail-types` | The RFC 9396 authorization details types the organisation accepts: each `type`, the `fields` it may carry and those `required`, its `description`, and the `clients` that may ask for it (those a token limited to named applications may see). `config:read` |
| `PUT /admin/organizations/{orgID}/authorization-detail-types` | `{"type": "payment_initiation", "fields": ["actions", "locations"], "required": ["actions"], "description"}` registers a type or replaces its fields, as `signari rar register` does. The fields are RFC 9396 section 2.2's common data fields alone (`locations`, `actions`, `datatypes`, `identifier`, `privileges`), at least one, with every required one among them; anything else is `400 invalid_authorization_details_type`. No client may ask for it until its `authorization_detail_types` names it (`PATCH /admin/clients/{clientID}`). Audited `admin.authorization_details_type_set`; `organizations:write`, honours `If-Match` |
| `DELETE /admin/organizations/{orgID}/authorization-detail-types` | `?type=` forgets the type and every client's leave to ask for it; `404 authorization_details_type_not_found` for one the organisation does not have. Audited `admin.authorization_details_type_removed` |
| `GET /admin/organizations/{orgID}/prompts` | The prompts asked between authentication and the session (terms, notices), in the order they are asked: `slug`, `title`, `body`, `once`, `order`, the `fields` a person answers, `enabled`, the current `version` and how many people `answered` it. `config:read` |
| `PUT /admin/organizations/{orgID}/prompts/{slug}` | `{"title", "body", "once", "order", "fields": [{"name", "type", "label", "required", "options", "attribute"}]}` defines or replaces the prompt, as `signari prompt set` does with its file. Checked before it is stored: a prompt nobody can answer, or a field writing an attribute the organisation did not declare or whose type its answers do not fit, is `400 invalid_prompt`. A change to the title, body or fields moves the `version`, and everyone who answered an earlier one is asked again (`asked_again`); `once` is true unless set false. There is no `DELETE`: a prompt's answers are the record of what people agreed to, so a prompt is disabled instead. Audited `admin.prompt_set`; `organizations:write`, honours `If-Match` |
| `PATCH /admin/organizations/{orgID}/prompts/{slug}` | `{"enabled": false}` takes the prompt out of service, neither asked nor answerable, keeping its answers; `true` puts it back, as `signari prompt disable` and `enable` do. Audited `admin.prompt_updated` |
| `GET /admin/organizations/{orgID}/registration` | Dynamic client registration (RFC 7591) at `/oauth2/register`: `enabled`, `open` (anyone who can reach it may register; otherwise an initial access token is needed), `max_clients` (the ceiling), the `allowed_scopes` a registered client may ask for, and `allow_confidential` (a registrant asking for a secret gets one; otherwise every registered client is public). Off when never set. `config:read` |
| `PUT /admin/organizations/{orgID}/registration` | `{"open": false, "max_clients": 100, "allowed_scopes": [], "allow_confidential": false}` turns registration on with the whole policy, as `signari registration enable` does, so `open` and `allow_confidential` are off unless asked for each time; `max_clients` 0 is 100 and no scopes is `openid profile email`. A token limited to named applications is `403 outside_token_clients`, since registrants make applications it never names. Audited `admin.registration_policy_set`; `organizations:write`, honours `If-Match` |
| `DELETE /admin/organizations/{orgID}/registration` | Turn registration off, keeping its policy and tokens for when it is turned on again; `404 registration_off` when it was off. Audited `admin.registration_disabled` |
| `GET /admin/organizations/{orgID}/registration-tokens` | The organisation's initial access tokens: `id`, `name`, `remaining` (null for unlimited), `expires_at`, `revoked_at` and `created_at`. Never a secret. `config:read` |
| `POST /admin/organizations/{orgID}/registration-tokens` | `{"name": "partner", "uses": 1, "expires_in_s": 86400}` mints an initial access token, as `signari registration token` does, and answers it once as `token`; `uses` and `expires_in_s` 0 are unlimited and never. Callers present it as `Authorization: Bearer` at `/oauth2/register`. Refused for a token limited to named applications, as the `PUT`. Audited `admin.registration_token_created`, without the secret |
| `DELETE /admin/organizations/{orgID}/registration-tokens/{tokenID}` | Revoke one, as `signari registration revoke` does: `/oauth2/register` refuses it from the next request. `404 registration_token_not_found` for none unrevoked with that id. Audited `admin.registration_token_revoked` |
| `GET /admin/organizations/{orgID}/radius-clients` | The network devices that may send Access-Requests (see [radius.md](radius.md)): each one's `id`, `name`, the `network` it sends from and whether it is `enabled`. Never a secret. `config:read`; registered with a root key |
| `POST /admin/organizations/{orgID}/radius-clients` | `{"name": "office wifi controller", "network": "10.0.0.0/24", "secret": "<shared secret configured on the device>"}` registers one, as `signari radius add-client` does, sealing the secret; it is never answered or recorded. A secret under 16 characters is `400 invalid_secret`; a range that is not a CIDR, or covers every address in any spelling, is `400 invalid_network`; a range the organisation already registered is `409 already_exists`. The answer gives the `network` as stored, IPv4-mapped spellings read as the IPv4 range they mean. Refused `403 outside_token_objects` to a token limited to named applications or groups. Running listeners pick it up within a minute. Audited `admin.radius_client_added`; `organizations:write` |
| `PATCH /admin/organizations/{orgID}/radius-clients/{deviceID}` | `{"enabled": false}` revokes the device, as `signari radius disable-client` does, and `true` restores it; listeners pick it up within a minute. It does not end sessions already established through the device: RADIUS cannot reach back into a switch. `404 radius_client_not_found` for an id the organisation does not have. Audited `admin.radius_client_updated` |
| `GET /admin/organizations/{orgID}/radius-authorizations` | What each authorised group's members are given at Access-Accept, highest `priority` first: `group_id`, `group`, `vlan_id` (null for none), `filter_id`. A token limited to some groups sees theirs only. `config:read` |
| `PUT /admin/groups/{groupID}/radius` | `{"vlan_id": 42, "filter_id": "staff", "priority": 10}` places the group's members on a VLAN, a Filter-Id naming a filter list on the device, or both, as `signari radius authorize` does, replacing what the group carried. Somebody in several authorised groups gets the highest priority, ties broken by group id. Neither a VLAN nor a Filter-Id, a VLAN outside 1 to 4094 (RFC 3580 section 3.31), or a Filter-Id over 253 characters is `400 invalid_radius_authorization`. Members already connected keep what they were given until they are re-authorised. Audited `admin.radius_authorization_set`; `groups:write`, within the token's groups, and `privileged-users:write` for a group whose members may impersonate |
| `DELETE /admin/groups/{groupID}/radius` | Take the group's VLAN and Filter-Id away, as `signari radius authorize -remove` does. `404 radius_authorization_not_found` when it carried none. Audited `admin.radius_authorization_removed` |
| `GET /admin/organizations/{orgID}/saml-providers` | The organisation's SAML service providers (see [saml.md](saml.md)): each one's `id`, `entity_id`, `name`, `name_id_format`, `signature_alg`, `enabled`, whether it signs assertions and responses, wants signed requests, is `encrypted` and `has_signing_cert`, the assertion `lifetime_s`, its `acs_urls` and `slo_urls`, its `attribute_release` (SAML attribute name to local attribute) and its `group_release` (null for none). `config:read` |
| `POST /admin/organizations/{orgID}/saml-providers` | `{"entity_id": "https://grafana.example.com/metadata", "name": "Grafana", "acs_url": "https://grafana.example.com/login/saml/acs", "name_id_format": "persistent", "slo_url": "", "slo_binding": "HTTP-Redirect", "signing_cert": "<PEM>", "encryption_cert": "<PEM>", "key_transport": "rsa-oaep-mgf1p", "want_signed_requests": false}` registers one, as `signari saml add-sp` does. The ACS URL is `https` with no wildcard; a logout URL or signed requests need a signing certificate; the encryption certificate is RSA of 2048 bits or more and not the signing one. Any of that, or a certificate that is not PEM, is `400 invalid_saml_provider`. An entity id registered already, in any organisation, is `409 already_exists`, since the SSO endpoint names no organisation. Refused `403 outside_token_objects` to a token limited to named applications or groups. Audited `admin.saml_provider_added`; `organizations:write` |
| `PATCH /admin/organizations/{orgID}/saml-providers/{providerID}` | `{"sign_assertions": true, "sign_responses": true, "lifetime_s": 300, "signature_alg": "ecdsa-sha256"}`, any of them, as `signari saml signing` does; what is not given is left as it is. Signing neither, a lifetime outside 30 to 3600 seconds, or an algorithm with no active key of its kind in the instance is `400 invalid_saml_provider`. After a new algorithm the answer says `metadata_changed`: the provider must fetch the metadata again before its next sign-in. `404 provider_not_found`. Audited `admin.saml_signing_set` |
| `PUT /admin/organizations/{orgID}/saml-providers/{providerID}/attribute-release` | `{"saml_attribute": "http://schemas.xmlsoap.org/claims/Department", "attribute": "department"}` releases a declared local attribute under that name in every assertion to the provider, as `signari saml attribute-release` does; an undeclared one is `400 invalid_saml_provider`. Audited `admin.saml_attribute_released` |
| `DELETE /admin/organizations/{orgID}/saml-providers/{providerID}/attribute-release` | `?saml_attribute=...` stops releasing it, as `signari saml attribute-release -remove` does. `404 release_not_found`. Audited `admin.saml_attribute_withdrawn` |
| `PUT /admin/organizations/{orgID}/saml-providers/{providerID}/group-release` | `{"attribute_name": "groups", "only": ["engineering"]}` tells the provider of those groups, as `signari saml group-release` does; an empty `only` releases every group the person is in. A group the organisation lacks is `400 invalid_saml_provider`. Audited `admin.saml_group_release_set` |
| `DELETE /admin/organizations/{orgID}/saml-providers/{providerID}/group-release` | Stop telling the provider of group membership. `404 release_not_found`. Audited `admin.saml_group_release_removed` |
| `GET /admin/organizations/{orgID}/identity-providers` | The providers the organisation's people sign in through and the issuers whose assertions it accepts (see [social-login.md](social-login.md)): each one's `id`, `slug`, `name`, `kind`, `issuer`, `enabled`, `allow_signup`, `allow_linking`, `allow_assertions` (the RFC 7523 jwt-bearer grant), `trust_email_verification`, `require_verified_email`, the `mfa_amr` and `mfa_acr` that count as multi-factor, how many accounts are `linked`, and its `attribute_map`. Never a client secret. `config:read` |
| `POST /admin/organizations/{orgID}/identity-providers` | Registers a provider, as `signari idp add` and `idp add-issuer` do: `{"kind": "google", "slug": "google", "client_id": "...", "client_secret": "..."}` for a named provider; `{"kind": "oidc", "slug": "corp", "client_id": "...", "client_secret": "...", "issuer": "https://login.example.com", "trust_email_verification": false}` for a generic one, discovered before anything is stored; `{"kind": "saml", "slug": "adfs", "entity_id": "...", "sso_url": "https://...", "certificate": "<PEM>", "name_id_format": "persistent", "allow_unsolicited": false, "force_authn": false, "skew_seconds": 30}` for a SAML upstream; `{"kind": "assertion", "slug": "ci", "issuer": "https://token.actions.githubusercontent.com", "jwks_url": "https://.../jwks"}` for an issuer whose JWTs the jwt-bearer grant may accept, its keys read first and its assertions refused until `allow_assertions` is set. `name`, `allow_signup` and `allow_linking` (on, and off for an issuer) too. The provider is reached through the client the sign-in uses, so an issuer that does not answer, declares another issuer or is on an internal address is `400 invalid_identity_provider`; so is a slug that is not lowercase letters, digits and hyphens, an unknown kind, a missing client, belief asked of a named provider, a `transient` NameID, a plaintext SSO URL, a certificate that does not parse or has expired, or a clock tolerance past 300 seconds. A slug any organisation has is `409 already_exists`, since `/login/with/<slug>` names no organisation. The answer gives the `sign_in_path` and `callback_path` to register with the provider (the ACS and metadata paths for SAML, the number of `keys` for an issuer); the secret is sealed and never answered. Refused `403 outside_token_objects` to a token limited to named applications or groups. Audited `admin.identity_provider_added`; `organizations:write`; registered with a root key |
| `PATCH /admin/organizations/{orgID}/identity-providers/{slug}` | `{"enabled": false, "allow_assertions": true, "trust_email_verification": true, "require_verified_email": true, "mfa_amr": ["mfa", "hwk"], "mfa_acr": []}`, any of them, as `signari idp disable`, `enable`, `assertions`, `verified-email` and `trust-mfa` do; what is not given is kept. Out of service, every way in through the provider is refused from the next request, its links kept and sessions already made through it not ended. A believed `email_verified` puts the address on the account as verified, so believe only a provider that verifies addresses itself; belief is set for a generic OIDC provider or a SAML upstream, and asking it of a named provider, whose behaviour is known, is `400 invalid_identity_provider`. So are multi-factor values on a GitHub or SAML provider, which sends no ID token for them to be read from, and either email setting on an assertion issuer. An address never finds or links an account. `404 provider_not_found`. Refused `403 outside_token_objects` to a token limited to named applications or groups. Audited `admin.identity_provider_updated`; `organizations:write` |
| `PUT /admin/organizations/{orgID}/identity-providers/{slug}/attribute-map` | `{"claim": "department", "attribute": "department", "overwrite": false, "max_length": 256}` routes a claim from the provider into a declared local attribute at each sign-in, as `signari idp attribute-map` does; `overwrite` lets a sign-in replace a value an administrator set by hand. An undeclared attribute is `400 invalid_identity_provider`: declare it first, since it carries whether its values are sealed. Audited `admin.idp_attribute_mapped` |
| `DELETE /admin/organizations/{orgID}/identity-providers/{slug}/attribute-map` | `?claim=department&attribute=department` stops the claim reaching the attribute, as `signari idp attribute-map -remove` does. `404 mapping_not_found`. Audited `admin.idp_attribute_unmapped` |
| `GET /admin/organizations/{orgID}/directories` | The directories the organisation's accounts follow (see [directory-sync.md](directory-sync.md)): each source's `id`, `slug`, `name`, `kind` (`google`, `entra` or `ldap`), `on_missing`, `enabled`, `dry_run`, `fetch_groups`, its `max_deactivate_percent` ceiling, what its last sync did (`last_sync_at`, `last_created`, `last_updated`, `last_deactivated`, `last_error`), and its `group_map`. Never credentials. `config:read`; registered with a root key |
| `POST /admin/organizations/{orgID}/directories` | Registers a source, as `signari dir add` does: `{"kind": "google", "slug": "workspace", "credentials": {<service account key>}, "domain": "example.com", "impersonate": "admin@example.com"}`, `{"kind": "entra", "slug": "tenant", "credentials": {<credential JSON>}}`, or `{"kind": "ldap", "slug": "corp", "ldap_url": "ldaps://dc01:636", "ldap_bind_dn": "...", "ldap_password": "...", "ldap_base_dn": "...", "ldap_flavour": "ad", "ldap_ca_pem": "..."}`; `filter`, `fetch_groups` and `group_attribute` too. Credentials and the bind password are sealed and never answered. It starts in dry run. Credentials that do not parse, a plaintext LDAP bind, an unknown flavour or kind is `400 invalid_source`; a slug the organisation has is `409 already_exists`. An LDAP source needs a deployment-wide token (`403 outside_token_organisation`), since the engine dials its URL from inside the deployment's network. Refused `403 outside_token_objects` to a token limited to named applications or groups. Audited `admin.directory_source_added`; `organizations:write` |
| `PATCH /admin/organizations/{orgID}/directories/{slug}` | `{"on_missing": "deactivate", "max_deactivate_percent": 10, "enabled": true, "dry_run": false, "fetch_groups": true, "group_attribute": "memberOf"}`, any of them, as `signari dir set` does; what is not given is kept, so changing one never resets the removal ceiling. `404 source_not_found`. Audited `admin.directory_source_updated` |
| `PUT /admin/organizations/{orgID}/directories/{slug}/group-map` | `{"remote_group": "cn=staff,ou=groups,dc=corp", "group": "staff"}` says the directory group grants that local group, as `signari dir group-map` does; a sync grants nothing that is not mapped. A group whose members may impersonate is `409 group_impersonates`, since whoever administers the directory could add themselves; an unknown group is `404 group_not_found`. Audited `admin.directory_group_mapped` |
| `DELETE /admin/organizations/{orgID}/directories/{slug}/group-map` | `?remote_group=...&group=...` stops it, as `signari dir group-map -remove` does; memberships it granted are left, and the next sync leaves the group alone. `404 mapping_not_found`. Audited `admin.directory_group_unmapped` |
| `POST /admin/organizations/{orgID}/directories/{slug}/sync` | `{"apply": true}` reconciles the organisation with the directory, as `signari dir sync -apply` does, answering how many people are `upstream` and were `active_before`, the `plan` and the `groups` pass as the command prints them, and whether it was `applied`; `{"apply": false}`, or a source configured for `dry_run`, writes nothing. The directory is called before anything is recorded, so `If-Match` is checked first. A plan past the removal ceiling is `409 sync_refused` with the plan; a directory that would not answer is `502 sync_failed`, recorded on the source too; `404 source_not_found` for none enabled. Audited `admin.directory_synced` |
| `GET /admin/organizations/{orgID}/scim-sources` | The upstreams that provision people into the organisation through `/scim/v2` (see [scim-source.md](scim-source.md)): each one's `id`, `slug`, `name`, `on_delete`, whether it is `enabled`, when it was `last_seen_at`, and how many people it `linked`. Never a token. `config:read` |
| `POST /admin/organizations/{orgID}/scim-sources` | `{"slug": "hr-directory", "name": "HR directory", "on_delete": "deactivate"}` registers one, as `signari scim-source add` does, and answers its bearer `token` **once**: 32 random bytes, stored only as a hash, which can create and deactivate every person in the organisation. `on_delete` is `deactivate` (the default), which keeps a deprovisioned person's history, or `delete`, which destroys it (`400 invalid_on_delete` otherwise); a slug the organisation has is `409 already_exists`. Refused `403 outside_token_objects` to a token limited to named applications or groups. Audited `admin.scim_source_added`; `organizations:write` |
| `PATCH /admin/organizations/{orgID}/scim-sources/{slug}` | `{"enabled": false}` takes it out of service, as `signari scim-source disable` does: its token is refused from the next request, and its links and settings are kept; `true` puts it back. `404 source_not_found`. Audited `admin.scim_source_updated` |
| `GET /admin/organizations/{orgID}/scim-targets` | The systems the organisation's people are written out to (see [scim.md](scim.md) and [provisioning.md](provisioning.md)): each target's `id`, `slug`, `name`, `kind` (`scim`, `google` or `entra`), `base_url`, `on_deactivate`, the `scope_group` it is limited to (empty for everybody), `dry_run`, `enabled`, how many people it holds (`linked`) and how many of those it holds and should not (`should_be_gone`). Never a token or credentials. `config:read`; registered with a root key |
| `POST /admin/organizations/{orgID}/scim-targets` | `{"slug": "slack", "base_url": "https://api.slack.com/scim/v2", "token": "<bearer the target issued>", "on_deactivate": "deactivate", "dry_run": false}` registers a SCIM target, as `signari scim add` does, or `{"kind": "google", "slug": "workspace", "credentials": {<service account JSON>}, "impersonate": "admin@acme.com", "target_domain": "acme.com"}` a native one, as `signari provision add` does; the token or credentials are sealed and never answered. Nothing is sent until it is synced. `on_deactivate` is `deactivate` (the default), `delete` or `nothing`. A SCIM target without an `https` base URL or a token, a Google one without an administrator or domain, credentials that do not parse, or an unknown kind is `400 invalid_target`; a base URL reaching a private address is `400 invalid_url`; a slug the organisation has is `409 already_exists`. Refused `403 outside_token_objects` to a token limited to named applications or groups. Audited `admin.scim_target_added`; `organizations:write` |
| `PATCH /admin/organizations/{orgID}/scim-targets/{slug}` | `{"enabled": false}` takes it out of service, as `signari scim disable` does: syncs skip it and its links are kept, so people deactivated meanwhile keep their access there until it is enabled and synced. `{"scope_group": "engineering"}` limits it to that group's members, as `signari scim scope` does, and `""` widens it to everybody; the next sync deprovisions whoever falls out. `404 target_not_found` or `404 group_not_found`. Audited `admin.scim_target_updated` |
| `PUT /admin/organizations/{orgID}/scim-targets/{slug}/groups/{group}` | Create the organisation's group at the target and record that this deployment owns it, as `signari scim provision-group` does; members are added by the next sync. The target is called before anything is recorded, so `If-Match` is checked before the call and the record written after it. A target that is disabled, not SCIM, or in dry-run mode is `409 target_unavailable`; a group already provisioned is `409 already_provisioned` with its `remote_id`; one the target refuses is `502 target_failed`. Audited `admin.scim_group_provisioned` |
| `DELETE /admin/organizations/{orgID}/scim-targets/{slug}/groups/{group}` | Delete that group at the target and forget it, in that order, as `signari scim deprovision-group` does; the local group is untouched. `404 group_not_provisioned` for one this deployment never created there. Audited `admin.scim_group_deprovisioned` |
| `POST /admin/organizations/{orgID}/scim-targets/{slug}/sync` | `{"apply": true}` converges the target on who should have an account there, as `signari scim sync -apply` does: accounts `created`, `deactivated` or `deleted`, how many `failed` and why in `failures`, and each provisioned group's members to `add` and `remove`. `{"apply": false}` answers the same counts and sends nothing but the reads a group's members need. A pass that stopped part-way is `502 sync_incomplete` with what it did and `error_detail`. `404 target_not_found`, or `409 target_unavailable` for a disabled one. Audited `admin.scim_target_synced` with the counts |
| `GET /admin/organizations/{orgID}/ssf-streams` | The relying parties' Shared Signals streams (see [ssf-caep.md](ssf-caep.md)): each one's `id`, `client_id`, `delivery_method` (`push` or `poll`), `endpoint`, `status`, the `events` it carries, and whether it `has_receiver_token`. Never the token. A token limited to named applications sees theirs only. `clients:read`; registered with a root key |
| `POST /admin/organizations/{orgID}/ssf-streams` | `{"client_id": "portal", "endpoint": "https://receiver.example.com/events", "receiver_token": "...", "events": [...]}` registers a pushed stream, or `{"client_id": "portal", "poll": true}` one the receiver pulls from `/ssf/poll`, as `signari ssf add-stream` does; the token is sealed and never answered. Events default to session-revoked. A poll stream with an endpoint or token, a pushed one without an `https` endpoint, or an event this engine does not emit is `400 invalid_stream`; an endpoint reaching a private address is `400 invalid_url`; a client the organisation does not have is `404 client_not_found`, and one with a stream already is `409 already_exists`. The application administrators sign in to the Admin API through needs `privileged-users:write` too (`403 privileged_target`). Audited `admin.ssf_stream_added`; `clients:write`, within the token's applications |
| `PATCH /admin/clients/{clientID}/ssf-stream` | `{"status": "paused", "reason": "receiver maintenance"}` pauses, disables or re-enables the client's stream, as `signari ssf set-status` does, telling the receiver with a stream-updated event as SSF 1.0 requires; disabling discards what it held. Answers the status it `was`. `404 stream_not_found` for a client with none. Audited `admin.ssf_stream_status_set`; `clients:write` |
| `GET /admin/organizations/{orgID}/ssf-sources` | The transmitters whose events the organisation acts on (see [shared-signals-receiver.md](shared-signals-receiver.md)): each one's `id`, `name`, `issuer`, `jwks_uri`, `audience`, the `events` it may send, the `critical_members` that make an event be discarded unless understood, and whether it is `enabled`. `config:read` |
| `PUT /admin/organizations/{orgID}/ssf-sources` | `{"name": "Upstream IdP", "issuer": "https://idp.example.com", "jwks_uri": "https://idp.example.com/keys", "audience": "https://id.example.com", "events": [...], "critical_members": []}` accepts events from a transmitter, or replaces what one with that issuer may send, as `signari ssf add-source` does. Name, issuer, audience and at least one event are required, and the `jwks_uri` must be `https` and not reach a private address (`400 invalid_source`). An issuer and audience another organisation's source has is `409 audience_taken`, since the receiver chooses a source by that pair. Refused `403 outside_token_objects` to a narrowed token, because a session-revoked event signs somebody out. Audited `admin.ssf_source_set`; `organizations:write` |
| `GET /admin/organizations/{orgID}/authorization-model` | The organisation's authorization model (see [authorization.md](authorization.md)) as it was written, in `source`; empty when there is none, and then nothing is permitted. `config:read` |
| `PUT /admin/organizations/{orgID}/authorization-model` | `{"source": "types: ..."}` stores a model, as `signari authz set-model` does. It is parsed and its own `tests` run first, and a model with none, one that will not parse, or one whose tests fail is `400 invalid_model` naming why; nothing is stored. Answers how many `types` and `actions` it defines and `tests_passed`. Refused `403 outside_token_objects` to a token limited to named applications or groups. Audited `admin.authorization_model_set`; `organizations:write` |
| `PUT /admin/organizations/{orgID}/relations` | `{"subject": "user:alice@example.com", "relation": "owner", "object": "document:42"}` grants the relation, as `signari authz grant` does, from the next decision; granting one already held keeps it. Subject and object are `type:id` (`400 invalid_relation`). Refused `403 outside_token_objects` to a narrowed token. Audited `admin.relation_granted`; `organizations:write` |
| `DELETE /admin/organizations/{orgID}/relations` | `?subject=user:alice@example.com&relation=owner&object=document:42` revokes it, as `signari authz revoke` does. `404 relation_not_found` when nothing matched, which is usually a misspelt reference with the grant meant still in place. Audited `admin.relation_revoked` |
| `POST /admin/organizations/{orgID}/config` | `{"document": "version: 1\ngroups: [...]", "prune": false, "dry_run": true}` plans a configuration file (see [config-as-code.md](config-as-code.md)), as `signari plan` does, writing nothing: the `changes` (each `action`, `kind`, `name`, `detail`, and whether it is `destructive`), how many `create`, `update` and `delete`, and the `config_version` it was computed against, also as the `ETag`. Without `dry_run` it applies the plan in one transaction, as `signari apply` does; send the plan's version as `If-Match` and an apply over a deployment that moved since is `412`. `prune` deletes what the file does not declare. A file the deployment already matches changes nothing and moves no version. A file that will not parse is `400 invalid_config`; one naming another organisation in `org:` is `400 org_mismatch`; a plan the configuration layer refuses, such as a client another organisation registered or a scope nobody declared, is `400 config_refused`. A file naming a secret by reference (`secret: {env: …}` or `{file: …}`) is `400 secret_reference`, dry run or not: a reference is read where `signari apply` runs, and read here it would be the server's. Without one, a provider or event subscription the apply creates is given a minted signing secret, answered once under `minted` (each `kind`, `name` and `secret`) and never again. Each change also needs its own route's scope, `403 insufficient_scope` naming it otherwise: `clients:write` for a client, `groups:write` for a group, and `privileged-users:write` for the application administrators sign in to the Admin API through or a group whose members may impersonate. Refused `403 outside_token_objects` to a token limited to named applications or groups. Audited `admin.config_applied` with the counts, and each change `config.applied`; `organizations:write` |
| `GET /admin/organizations/{orgID}/access-policy` | The access policy in force (see [policy.md](policy.md)): the `document` as it was applied and `applied_at`, or an empty document and a null `applied_at` when there is none, which allows everything. `config:read` |
| `PUT /admin/organizations/{orgID}/access-policy` | `{"document": "version: 1\npolicies: [...]"}` puts the file in force, as `signari policy apply` does, from the next decision. It is parsed and its own `tests` run first; one that will not load, or whose tests disagree with it, is `400 invalid_policy` naming the line or the failing case, and nothing is stored. Answers the policy's `summary`. Refused `403 outside_token_objects` to a token limited to named applications or groups. Audited `admin.access_policy_applied` with the document's SHA-256; `organizations:write` |
| `GET /admin/organizations/{orgID}/sign-in-flow` | The sign-in flows applied (see [flows.md](flows.md)), as the access policy is read; none runs the built-in flows. `config:read` |
| `PUT /admin/organizations/{orgID}/sign-in-flow` | `{"document": "..."}` applies a flow file, as `signari flow apply` does; engines pick it up within thirty seconds. A file that will not load, whose tests fail, or that admits a session without authenticating somebody is `400 invalid_flow`, and nothing is stored. Answers the file's `summary` and, in `not_executed`, any flow declared for a journey this engine does not walk, which is stored and governs nothing. Refused `403 outside_token_objects` to a narrowed token. Audited `admin.sign_in_flow_applied` with the document's SHA-256; `organizations:write` |
| `GET /admin/organizations/{orgID}/rac-connections` | The machines people reach through the browser (see [remote-access.md](remote-access.md)): each one's `id`, `slug`, `name`, `protocol`, `host`, `port`, the `require_group` whose members may reach it (empty for anybody, subject to policy), whether it is `recorded` (never where), `enabled`, whether it `has_credentials`, and its guacd `parameters`. Never a credential. `config:read`; registered with a root key |
| `POST /admin/organizations/{orgID}/rac-connections` | `{"slug": "finance-desk", "name": "Finance desktop", "protocol": "rdp", "host": "10.0.4.21", "login": "svc-desk", "password": "…", "require_group": "finance"}` registers one, as `signari rac add` does, sealing the login and password; neither is answered or recorded. `port` defaults to the protocol's own. `protocol` is `rdp`, `vnc` or `ssh` (`400 invalid_protocol`); a `require_group` the organisation does not have is `400 unknown_group`, since a machine restricted to a group nobody can be in reaches nobody; a slug the organisation has is `409 already_exists`. A recording path is set only by the command. Refused `403 outside_token_objects` to a token limited to named applications or groups. Audited `admin.rac_connection_added`; `organizations:write` |
| `PATCH /admin/organizations/{orgID}/rac-connections/{slug}` | `{"enabled": false}` takes it out of service, as `signari rac disable` does: it is neither listed nor connectable from the next request, and a session already open runs until it closes; `true` puts it back. `{"parameters": {"<name>": "<value>"}}` replaces its guacd parameters, as `signari rac set-parameters` does, and `{}` clears them. A parameter the connection's own settings supply (the host, port, credentials or recording path) is `400 reserved_parameter`; one whose name contains `path` is `400 parameter_names_a_path`, since it names a location on the machine guacd runs on, and is set by the command. `404 connection_not_found` for a slug the organisation does not have. Audited `admin.rac_connection_updated`, naming the parameters and never their values |
| `GET /admin/organizations/{orgID}/outposts` | The organisation's outposts (see [outposts.md](outposts.md)): each one's `id`, `name`, `kind`, whether it is `enabled`, its `search_group` (empty: each person behind it sees only their own entry), and when and from where it was last heard from (`last_seen_at`, null if never, and `last_seen_ip`). Never a token. `config:read` |
| `POST /admin/organizations/{orgID}/outposts` | `{"name": "dmz-ldap", "kind": "ldap", "search_group": "ldap-readers"}` registers one, as `signari outpost create` does, and answers its `token` **once**: it is stored hashed. `kind` is `ldap`, `radius`, `proxy`, `desktop` or `pdp` (`400 invalid_kind`), since the token is bound to one protocol. A search group on anything but an LDAP outpost, or naming no group in the organisation, is `400 invalid_search_group`; a name the organisation has is `409 already_exists`. Refused `403 outside_token_objects` to a token limited to named applications or groups, since an outpost verifies anybody's password. Audited `admin.outpost_created`; `organizations:write` |
| `PATCH /admin/organizations/{orgID}/outposts/{name}` | `{"enabled": false}` takes it out of service, as `signari outpost disable` does: the core refuses its token from its next request and keeps its settings; `true` puts it back. `{"search_group": "ldap-readers"}` sets whose members may search the whole directory through it, as `signari outpost search-group` does, and `""` clears it; the core applies it from its next request, and the outpost should be restarted to decide with the same value. `404 outpost_not_found` for a name the organisation does not have. Audited `admin.outpost_updated` |
| `DELETE /admin/organizations/{orgID}/signup` | Close self-sign-up, as `signari signup disable` does; invitations and administrators still make accounts. `404 signup_off` when it was closed. Audited `admin.signup_rule_removed` |

**Only an unscoped token may create an organisation.** A token scoped to one
organisation is refused, because a tenant that can provision tenants has escaped
the isolation the rest of the product enforces: it could create a sibling and
then act on it. This reuses the same `MayActOn` check every other write uses
rather than adding a second boundary that has to be kept in step.

**There is no `DELETE`,** and that is a decision. Every user, client, session,
token and audit event in a deployment hangs off an organisation, so a one-call
tenant deletion is irreversible destruction of everything a customer has,
reachable by one mistyped identifier. Removing the data is a deliberate operation
done with the database in front of you: `signari instance org-delete`, which
says what would go and asks for a code to confirm it, on an organisation
suspended first. Stopping a tenant without destroying it is the `PATCH` above,
and taking its configuration elsewhere is `signari export org`.

### Scopes

| | |
|---|---|
| `GET /admin/organizations/{orgID}/webauthn-policy` | The organisation's authenticator policy: `attestation`, `allowed_aaguids`, `refuse_cloned`, and the ceremony: `user_verification`, `resident_key`, `attachment`, `algorithms` (COSE numbers), `timeout_seconds`, `hints`. Needs `config:read` |
| `PUT /admin/organizations/{orgID}/webauthn-policy` | Set it, the same as `signari webauthn policy`. The whole policy is written each time: `refuse_cloned` left out means on, and a ceremony field left out takes its default. An allow-list without attestation, a model id that is not a uuid, an unknown conveyance, or a ceremony value the CLI would refuse is `400 invalid_policy`. Needs `organizations:write` |
| `GET /admin/organizations/{orgID}/scopes` | The organisation's declared scopes, plus the standard set. Needs `config:read` |
| `PUT /admin/organizations/{orgID}/scopes` | Declare or update one. Needs `organizations:write` |
| `DELETE /admin/organizations/{orgID}/scopes/{scope}` | Remove a declaration. Refused while a claim mapper requires it, `409 scope_in_use` with the count, since the mapper would then release nothing |
| `GET /admin/organizations/{orgID}/proxy-hosts` | The applications [forward auth](forward-auth.md) protects. Needs `config:read` |
| `PUT /admin/organizations/{orgID}/proxy-hosts` | Register one, or change whether it is enabled: `{"host": "grafana.example.com", "enabled": true}`. Needs `organizations:write` |
| `DELETE /admin/organizations/{orgID}/proxy-hosts/{host}` | Remove one |

**Declaring a scope adds no gate on a request.** A client already cannot ask for
a scope it is not registered for — that check runs at `/authorize`, the device
and CIBA endpoints, `jwt-bearer` and `client_credentials`, and none of it changes
here.

What declaring buys is that a scope stops being a word somebody typed twice.
Before this, `hr_records` existed only because the same string appeared in a
client's registered list and in a claim mapper's `required_scope`, with nothing
connecting them — so a typo in either was silent, and silent in the worst
direction: the mapper waits for a scope no client can be granted, the claim is
never released, and the configuration looks correct.

It also gives the consent screen something to say. `hr_records` tells a person
nothing, and a screen that cannot explain what is being asked for collects a
click rather than a decision.

`advertise` (default true) controls whether discovery lists it. A scope used only
between a first-party client and its own resource server is not something a
stranger needs to learn exists, and every advertised scope is a hint about what
this deployment holds.

**The standard scopes cannot be declared.** `openid`, `profile`, `email`,
`groups` and `offline_access` mean what the specifications say; a row appearing
to redefine one would be a setting that changes nothing.

### Clients

| | |
|---|---|
| `GET /admin/clients` | List, paged. `?limit=` (max 200) and `?cursor=` |
| `GET /admin/clients/{clientID}` | One client's whole configuration: every setting it has, by its column name (grant and response types, scopes, PKCE, token lifetimes, signing algorithm, authentication method and public `jwks`, mutual-TLS rule, logout endpoints, CIBA delivery, exchange, DPoP, hybrid review date, assertion issuers, claims redirects, portal fields and the rest), with its `redirect_uris` sorted. Never the secret hash or the registration token's. Until October 2026 it gave seven fields, so a caller could not compare a desired configuration with the server's |
| `POST /admin/clients` | Register a client. `require_pkce` defaults to `true` for confidential clients as well as public ones; `false` is an explicit opt-out and is refused for a public client |
| `PATCH /admin/clients/{clientID}` | `enabled`, `require_pkce`, `may_exchange` and `exchange_audiences`. Only the fields sent are changed, and the response gives what was set. `enabled: false` holds from the next request: the client's outstanding access tokens introspect as inactive and are refused by userinfo, token exchange, transaction tokens and the credential endpoint. A resource server that checks only the signature accepts them until they expire, at most the client's access-token lifetime. A public client cannot drop PKCE, and cannot be granted token exchange (`400 confidential_client_required`). `exchange_audiences` replaces the list of audiences the client may exchange tokens for besides itself; an entry with whitespace is `400 invalid_audience`. `post_logout_redirect_uris` (replaces the list), `frontchannel_logout_uri` (empty clears) and `frontchannel_logout_session_required` register sign-out, see [logout](logout.md#registering-a-clients-sign-out); a URI that breaks the redirect-URI rules is `400 invalid_logout_uri`. `access_token_ttl_s` (60 to 3600) and `refresh_token_ttl_s` (300 to 31536000) set the token lifetimes, as `signari client set-lifetimes` does, and `id_token_signed_response_alg` (ES256, RS256, PS256, EdDSA) what signs the client's tokens, as `signari client set-alg` does, refused unless the instance holds an active key of it; `require_pushed_authorization_requests` and `first_party` are the switches `client set-par` and `client set-first-party` set; `admin_api` designates the client for the Admin API, as `client set-admin-api` does, and needs `privileged-users:write` (see [Administrative roles](#administrative-roles)); changing, deleting or rotating the secret of a designated client needs it too (`403 privileged_target`); `issuer_alias` pins the client to a live alias of its instance (`""` clears), as `client set-issuer-alias` does; `minimum_acr` (`"1"` to `"4"`: a single factor, multi-factor, multi-factor with a passkey or security key, or with a key bound to its device) is the weakest authentication the client accepts, as `client set-acr` sets it; `consent_lifetime_s` (3600 to 315360000, or 0 for never) is how long a person's consent to it lasts before they are asked again, as `client set-lifetimes -consent-ttl` sets it; out of bounds is `400 invalid_client_setting`. Through the same code as their CLI verbs, so the two refuse alike: `grant_types` (`client set-grants`, each one this server dispatches), `backchannel_token_delivery_mode` and `backchannel_client_notification_endpoint` (`client set-ciba`; either alone keeps the other), `allow_hybrid` with `hybrid_review_by` (`client set-hybrid`, YYYY-MM-DD; `false` turns it off and takes `code id_token` out of the response types), `claims_redirect_uris` (`client set-claims-redirects`, https and no fragment), `dpop_bound_access_tokens` (`client set-dpop`), `exchange_requires_audience_match` (`client set-exchange-containment`) and `jwt_bearer_providers` (`client set-assertion-issuers`, each a provider of the client's organisation), and `authorization_detail_types`, the whole list of RFC 9396 types it may ask for, each one its organisation registered (`rar allow` adds one; `400 invalid_authorization_details_type` names one it did not). `jwks` (`client set-keys`: public keys only, and it moves the client to `private_key_jwt` and drops its secret) and the mutual-TLS rule (`client set-tls`: `tls_subject_dn`, `tls_san_dns`, `tls_san_uri`, `tls_san_ip`, `tls_san_email` or a self-signed `tls_certificate` in PEM, exactly one, which replaces the rule; `tls_bound_tokens` alone keeps it). And what only `signari apply` set, held as it holds them: `display_name`, `redirect_uris` (replaces the set, at least one, each by the shared redirect rules), `scopes` (each standard or declared for the organisation), `initiate_login_uri`, `logo_uri` and `portal_hidden`; and `backchannel_logout_uri` (https, no fragment, which a dynamic registration is now held to as well) and `backchannel_logout_session_required`, which nothing could set for a client registered by hand. Each change is audited with what it was and what it became. A field it cannot set (`client_type`, `org_id`, `created_at`, a misspelling) is `400 invalid_json` naming it; until October 2026 one was dropped and the answer was 200 |
| `DELETE /admin/clients/{clientID}` | Remove the client and everything issued under it. Real deletion, not a flag (ADR-005): every code, token, refresh family, consent, pushed request and device authorisation cascades with it. The audit trail keeps its records — `audit_events.client_id` has no foreign key, so the history of a client outlives the client. Returns `refresh_families_revoked`: the refresh token families that could still be redeemed and now cannot. Access tokens are signed JWTs recorded nowhere, so there is no count of them to give |
| `POST /admin/clients/{clientID}/rotate-secret` | New secret, shown once. The previous one stops working immediately |
| `GET /admin/clients/{clientID}/group-release` | Which groups the application is told of in the `groups` claim: `released` false for none, which is where every application starts, and otherwise `only_groups`, every group a person is in when it is empty. `clients:read` |
| `PUT /admin/clients/{clientID}/group-release` | `{"only_groups": ["staff", "admins"]}` tells the application of a person's membership of those groups from its next token, and `{"only_groups": []}` of every group, as `signari group release` does. A group the organisation does not have is `400 unknown_group`, naming it, rather than a release that tells nothing. The application must still ask for the `groups` scope. Audited `admin.group_release_set`; `clients:write`, and `privileged-users:write` for an application designated for the Admin API; honours `If-Match` |
| `DELETE /admin/clients/{clientID}/group-release` | Tell the application of no group from its next token; `404 not_released` when it was told of none. Audited `admin.group_release_removed`, scoped as the `PUT` |

### Users

| | |
|---|---|
| `GET /admin/users` | List, paged. Filters, any together: `email` (the exact address, whatever its case), `q` (a prefix of the address or the user name; `%` and `_` in it are characters, not wildcards) and `status` (`active`, `deactivated`, `locked` or `pending`). Each is served by an index, an exact address across organisations included |
| `GET /admin/users/{userID}` | One user: the list's fields and every one `PATCH` sets or clears, `display_name`, `given_name`, `surname`, `email_verified` (an address change clears it), `require_password_change`, `updated_at`, and `locale` (empty when the deployment's applies). No credential material |
| `POST /admin/users` | Create |
| `PATCH /admin/users/{userID}` | Activate (which approves a self-sign-up waiting, `pending`, for approval and tells the person they can sign in; audited with `approved: true`), deactivate, set a password, require a change, and edit identity: `email`, `username`, `display_name`, `given_name`, `surname`, and `locale`, the BCP 47 tag the person's notices and pages are written in, as `signari user locale` sets it (400 `invalid_locale` when it is not a tag). An empty string clears a field; both identifiers cannot be cleared at once (400 `no_identifier_left`), and a taken address or name is 409 `already_exists`. A password set, or an address changed, is told to the person on every channel, queued with the change; an address change goes to the old address too, naming neither |
| `DELETE /admin/users/{userID}` | Remove the person and everything they hold. Real deletion, not a flag (ADR-005). Their sessions are **terminated before the row goes**, so every relying party they reached receives a back-channel logout — letting the rows cascade away would destroy the list of who to notify before anyone was notified, and leave them signed in everywhere with an account that no longer exists. Returns `sessions_ended`, `notices_queued` and `refresh_families_revoked`, the refresh token families that could still be redeemed, whether or not a session held them. The audit trail keeps its records: `audit_events` has no foreign key to `users`, so what a person did outlives their account |

### Invitations

| | |
|---|---|
| `GET /admin/invitations` | List, paged, each `open`, `used`, `revoked` or `expired`; `?org_id=` narrows it. `users:read` |
| `POST /admin/invitations` | `org_id`, and optionally `email` (bind it to one address), `groups` (names the new account joins), `expires_in_seconds` (seven days by default, at most ninety) and `send`. Without `send` the response carries the `link`, once: only its hash is kept. With `send` it needs `email`, and the engine mails the link through the outbox, so the response has no link and neither does the outbox: the token is made as the mail goes out, again for each retry, so the newest mail is the one that works. Every group must exist and be one the token may act on (400 `no_such_group` otherwise, the same for a group outside a narrowed token), and a group whose members may impersonate needs `privileged-users:write` (403 `privileged_target`), as adding a member does. `users:write`. Audited `admin.invitation_created` |
| `DELETE /admin/invitations/{invitationID}` | Revoke an open one, so its link stops working at once; 404 for one used, revoked, expired or in another organisation. Audited `admin.invitation_revoked`, `via: admin_api` |

### User attributes

Operator-defined fields on a user, declared per organisation before anything can
be stored in them.

| | |
|---|---|
| `GET /admin/organizations/{orgID}/attributes` | The organisation's declarations: `id`, `name`, `display_name`, `value_type`, `personal`, `user_readable`, `user_writable` and `required`, the names a declaration is made with. Until October 2026 they came back as `ID`, `ValueType` and the like, unlike every other response. Needs `config:read` |
| `PUT /admin/organizations/{orgID}/attributes` | Declare or update one. Needs `organizations:write` |
| `GET /admin/users/{userID}/attributes` | One user's values. Needs `users:read` |
| `PUT /admin/users/{userID}/attributes` | Set values. Needs `users:write` |
| `DELETE /admin/users/{userID}/attributes/{name}` | Clear one of the person's values. An undeclared attribute is `404 unknown_attribute`, a value they do not have `404 attribute_not_set`; a required attribute is `409 attribute_required`, since it is given another value rather than emptied, as the person's own profile refuses too. A person who may impersonate needs `privileged-users:write`. Audited `admin.attribute_cleared`, by name only; `users:write` |

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

**A value must fit its attribute's type.** A `boolean` takes `true` or `false`
and a `number` takes a JSON number; anything else is `400
invalid_attribute_value`, which names the attribute and never the value. A
`string` holds anything, and a `date` is stored as given. Values are typed when
they are released as claims, so `yes` stored in a boolean went out as `false`.
For the same reason `value_type` can change only while the attribute holds no
values (`409 attribute_type_in_use`). A value an identity provider's mapping
supplies that does not fit is skipped, as one over its length limit is.

Reads report `readable: false` rather than an error when a personal value cannot
be unsealed, which happens for exactly one reason: the subject was erased.
"Destroyed on request" and "never set" are different facts, and an audit of
whether an erasure completed needs to tell them apart.

The audit trail records **which** attributes were declared or set, never their
values — writing those into an append-only table is precisely what the sealed
storage exists to avoid.

**What the person may do is part of the declaration.** `user_readable` shows the
attribute on their own `/account/profile`; `user_writable` (which implies
readable) lets them set it there and offers it on the sign-up form; `required`
makes the sign-up refuse to create the account without it and the profile
refuse to empty it. Their own writes go through the same typed, sealed write as
this API's, are refused for an attribute they may not write (rather than
skipped), and are audited `user.attributes_updated`, names only. An attribute
that is neither readable nor writable is the administrator's alone and appears
on no page the person sees. Until October 2026 all three were stored and
honoured nowhere.

### Claim mappers

Which attribute becomes which claim, where, and for whom.

| | |
|---|---|
| `GET /admin/organizations/{orgID}/claim-mappers` | Everything this organisation releases. Needs `config:read` |
| `POST /admin/organizations/{orgID}/claim-mappers` | Release an attribute as a claim. Needs `organizations:write` |
| `DELETE /admin/organizations/{orgID}/claim-mappers/{mapperID}` | Stop releasing it |
| `GET /admin/organizations/{orgID}/migration-source` | The provider this organisation is migrating off, without its secret, and how the cutover is going: people pending, people migrated through it, verifications accepted and refused. Needs `config:read`; `404 migration_source_not_found` when there is none |
| `PUT /admin/organizations/{orgID}/migration-source` | Create or replace it: `kind` `oidc_password` (`url` an https token endpoint, `client_id`, `client_secret`, `scope`) or `ldap` (`url` `ldaps://`, or `ldap://` with `start_tls`, a `bind_dn_template` with `{username}` once, and optionally `ca_pem`). A new source is disabled; `enabled` switches it, and is left as it is when absent. An empty `client_secret` keeps the stored one while `url` and `client_id` are unchanged; changing either without one is refused, since the stored secret was issued for the old provider and would go to the new endpoint. Anything the verifier would refuse is `400 invalid_migration_source`. Needs `organizations:write`. See [password migration](password-migration.md) |
| `DELETE /admin/organizations/{orgID}/migration-source` | Remove it. People still pending stay pending |
| `GET /admin/organizations/{orgID}/resource-servers` | The RFC 8707 resources this organisation's tokens may be audienced to, each `resource` and `name`. Needs `config:read`. See [resource indicators](resource-indicators.md) |
| `PUT /admin/organizations/{orgID}/resource-servers` | `{"resource": "https://api.example.com", "name": "Billing API"}`: register a resource server, or rename one registered. An absolute http(s) URI with no fragment, else `400 invalid_resource`. Needs `organizations:write` |
| `DELETE /admin/organizations/{orgID}/resource-servers` | `?resource=<uri>`: withdraw it: no new token is audienced to it, refreshes included. `404 resource_server_not_found` when it was not registered. Needs `organizations:write` |

**Nothing is released without a mapper.** An attribute that exists reaches no
token, for any client, in any destination, until somebody says so. The common
alternative — attributes flow into tokens automatically, a deny-list holds back
the sensitive ones — inverts the failure: adding an attribute becomes a
disclosure to every relying party already integrated, made by whoever added it.
A deployment that adds `national_insurance_number` to track something internal
has, in that shape, just sent it to a dozen third-party applications.

**`destination` and the audience are required, not defaulted.** A default would
be a disclosure nobody chose. `destination` is `id_token`, `userinfo` or
`access_token`, and the last is the one that travels furthest — it is presented
to resource servers the user never saw a consent screen for. For the audience,
either name a `client_id` or set `"all_clients": true`; an omitted field must
never be the thing that widens a disclosure to everybody.

**`required_scope` keeps consent meaningful.** A mapper that names one releases
nothing to a grant that does not carry it, so a user who declined `profile` does
not receive a token carrying their job title anyway. Leaving it empty releases
unconditionally, which is right for something every client needs to function.
A scope it names must be standard or declared by the organisation, or the mapper
is refused with `400 unknown_scope`: a typo used to make a mapper that released
nothing to anybody and looked configured. `signari doctor` names a mapper saved
before that check that waits for neither.

**A mapper cannot write a protocol claim.** `sub`, `iss`, `aud`, `exp`, `acr`,
`amr`, `cnf` and the rest are refused by the database. One writing `sub` would
let an organisation issue tokens impersonating any subject at every relying
party that trusts this issuer; `acr` and `amr` are what a relying party reads to
decide the authentication was strong enough. Mapped claims can only ever *add*.

An erased subject releases nothing — the value cannot be unsealed, and it is
omitted rather than reported, because a token is not a diagnostic surface.

### Second factors

| | |
|---|---|
| `GET /admin/users/{userID}/factors` | What the person can authenticate with: kind, label, whether the enrolment was completed, when it was created and last used, and `disabled` when an authenticator app was switched off for too many consecutive wrong codes. Recovery codes are reported as a **count of unused ones**, never listed, with `recovery_codes_disabled` for a set switched off the same way |
| `DELETE /admin/users/{userID}/factors/{kind}` | Remove a factor the user holds one of: `totp`, `email_otp`, `sms_otp`, `duo` — or every recovery code at once with `recovery`, which also clears a set's disabled state |
| `DELETE /admin/users/{userID}/factors/{kind}/{factorID}` | Remove one of several: `webauthn`, `recovery`. Either removal ends every session the person holds and queues a notice to them, by email and a verified number, which the server's outbox delivers; `signari user remove-factor` does the same |
| `DELETE /admin/users/{userID}/throttle` | Clear what wrong guesses charged to this person: the password step's growing delay, the sign-in form's per-account budget under their address and username, and the second-factor step's budget. For somebody sent to wait who cannot. The next wrong password is charged as before, and the per-address budgets, which belong to whoever is guessing, are left. Audited `admin.user_unlocked`; `users:write`, honours `If-Match` |
| `POST /admin/users/{userID}/passkey-link` | Email the person a link that registers one passkey with no session: for a new starter with no password, or somebody whose only way in is lost. Body `{"ttl_seconds": N}`, from 60 to 604800, or empty for a day. The answer names the link and its `expires_at`, **never its token**: the outbox mints that as it sends the email, keeps only its hash, and a new link ends the person's unused one. 409 for an account that is not active or has no address. Audited `admin.passkey_link_issued`, and `mfa.passkey_link_used` when it is spent; `users:write`, plus `privileged-users:write` for a privileged person; honours `If-Match`. `signari user passkey-link` does the same |

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

**Writes that touch impersonation also need `privileged-users:write`.** Setting
the flag was never possible here, but joining a flagged group was, and joining
is what grants the power. The same went for users: a `users:write` token could
change a flagged member's e-mail address, remove their factors, set their
attributes or delete them. Each of these let the lesser credential take over or
remove the greater one. The following are now refused with
`403 privileged_target` unless the token also holds `privileged-users:write`:

- any write on a group that may impersonate, including adding or removing a
  member;
- any write on a user who belongs to such a group: `PATCH` and `DELETE` on the
  user, factor removal, attributes and erasure.

The refusal is written to the audit trail as `admin.privileged_refused`.
Ending a privileged user's sessions is the exception and still needs only
`users:write`. It only takes access away, and an incident responder has to be
able to sign out a compromised administrator with the token they already hold.
A token scoped to another organisation gets that organisation's usual
refusal, so it cannot learn which ids belong to administrators. The OpenAPI
document marks the affected operations with `x-privileged-scope`.

A membership may not cross organisations: a group decides application access, so
joining a user from another tenant is refused with 400 even when the token could
act on both.

### Sessions

| | |
|---|---|
| `GET /admin/users/{userID}/sessions` | Live sessions for a user, newest first, paged with `limit` and `cursor` like the other lists. Until October 2026 it stopped at 200 with no way to see the rest |
| `DELETE /admin/users/{userID}/sessions` | End all of them |
| `GET /admin/users/{userID}/consents` | What the person sees at `/account/connected`: each application they consented to or that holds a live grant, with its scopes, when it was granted, how many refresh grants are live and until when an offline one lasts. A token narrowed to named clients sees only those. `users:read` |
| `POST /admin/users/{userID}/credential-offers` | `{"client_id": "wallet", "credential_configurations": ["staff-id"], "tx_code": true, "tx_code_length": 6, "expires_in_s": 300, "credential_issuer": "https://id.example.com"}` mints an OID4VCI Credential Offer for the person, as `signari credential offer` does, and answers it as `offer` and as the `offer_uri` a wallet opens (shown as a QR code or deep link), with `expires_at` and, when asked for, the `tx_code`. Whoever holds the offer, with its transaction code if it has one, redeems it into a token for the person through that client, so send the transaction code by another channel; both are answered once and kept only as hashes, and the answer is `Cache-Control: no-store`. The issuer defaults to the organisation's instance. A client of another organisation or one the token is not limited to, an unknown or repeated configuration, an offer lasting past an hour, a transaction code outside 4 to 12 digits or an issuer that is not `https` is `400 invalid_credential` (`403` for a client outside the token); a client not registered for the pre-authorized code grant is `409 client_cannot_redeem`. A person who may impersonate needs `privileged-users:write`. Audited `admin.credential_offered`, never the codes; `users:write` |
| `GET /admin/users/{userID}/identity-links` | The upstream subjects the person is linked to (see [jwt-bearer.md](jwt-bearer.md)): each one's `provider` slug, `kind`, `subject`, `linked_at`, and `last_sign_in_at` (null for a link nobody has signed in through). `users:read` |
| `PUT /admin/users/{userID}/identity-links/{slug}` | `{"subject": "repo:acme/deploy:ref:refs/heads/main"}` makes that subject at the organisation's provider act as the person, as `signari idp link` does: the jwt-bearer grant then mints tokens for the person from that issuer's assertions naming it, so whoever controls the subject there acts as them here. The same link again answers `changed: false` and moves no version. A subject that acts as somebody else, or a person known to the provider as another subject, is `409 link_taken`: a link is moved by removing it first. A provider of another organisation is `404 provider_not_found`. A person who may impersonate needs `privileged-users:write`. Audited `admin.identity_linked`; `users:write` |
| `DELETE /admin/users/{userID}/identity-links/{slug}` | Detach the person from the provider, as `signari idp unlink` does: the next assertion naming the subject is refused, and the grant issues no refresh token, so nothing outlives it. `404 link_not_found`. Audited `admin.identity_unlinked` |
| `DELETE /admin/users/{userID}/consents/{clientID}` | Withdraw the consent and revoke the application's refresh grants, through the same path the person's own removal takes, so the next authorization asks again and no refresh succeeds. Access tokens already issued run out on their own. Audited `admin.consent_revoked`; `users:write`; honours `If-Match` |
| `DELETE /admin/sessions/{sid}` | End one |

Revocation goes through the engine's single termination path, so every relying
party the person reached is sent a back-channel logout. Setting `revoked_at`
directly would end the session here and leave them signed in everywhere that
matters while this API reported success; the response returns `notices_queued` so
a caller can see the notices were raised.

The listing reports the user agent and whether an address is on file, never the
address. `ip_hash` is a hash by deliberate choice, and returning it would undo
that decision from the other side. Both are recorded when the session opens: the
`User-Agent` header with control characters removed, cut to 256 bytes, and an
HMAC of the address under a key derived from `SIGNARI_ROOT_KEY`. Keyed, because
there are only four billion IPv4 addresses, so a plain digest copied out of the
database would be reversed by trying them all. A deployment run without a root
key records no address hash.

### Audit trail

| | |
|---|---|
| `GET /admin/audit-events` | The trail, newest first. Cursor-paged. Filters: `event_type`, `subject_id`, `client_id`, `admin_token_id` (what one admin token did), `since`, `until` (RFC 3339). Each event carries the `admin_token_id` that made it, when one did; a change through the break-glass environment token, which has no row, carries `detail.break_glass: true`, and one made for a person the caller named in `Signari-Operator` carries `detail.operator`. Needs `audit:read` |

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
| `POST /admin/subjects/{subjectID}/erase` | Erase a person: crypto-shred their key and remove their account, ending its sessions and telling the applications. Permanent, and requires the identifier repeated in `confirm_subject_id`; an active account also needs `deactivate: true`. The answer says `key_shredded`, `account_deleted`, `sessions_ended` and `notices_queued` |
| `GET /admin/subjects/{subjectID}/export` | Everything kept about a person, as the [data-export.md](data-export.md) document: their rows from every table keyed by them, attributes unsealed, every credential's value withheld. Needs `subjects:export`. A read, so no version moves, but audited `admin.subject_exported` before it is answered. A token scoped to an organisation exports only its people, and a subject whose account is gone names no organisation, so only an unscoped token may export one. Registered only with a root key |

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
