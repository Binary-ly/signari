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

## Endpoints

Every mutation returns `config_version` in its body and `ETag` in its headers.

An id in a path (`{userID}`, `{groupID}`, `{subjectID}`, `{orgID}`, `{mapperID}`)
must be a uuid in its canonical form, lower case `8-4-4-4-12`, or the request is
`400 invalid_request`. PostgreSQL accepts other spellings of the same uuid, braced
or with a hyphen after every four digits, and a check that read an id more strictly
than the write it guarded once let a `users:write` token take over an administrator.
One spelling at the boundary means every check, write and audit record names the
row the same way.

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

### Scopes

| | |
|---|---|
| `GET /admin/organizations/{orgID}/webauthn-policy` | The organisation's authenticator policy: `attestation`, `allowed_aaguids`, `refuse_cloned`. Needs `config:read` |
| `PUT /admin/organizations/{orgID}/webauthn-policy` | Set it, the same as `signari webauthn policy`. `refuse_cloned` left out means on. An allow-list without attestation, a model id that is not a uuid, or an unknown conveyance is `400 invalid_policy`. Needs `organizations:write` |
| `GET /admin/organizations/{orgID}/scopes` | The organisation's declared scopes, plus the standard set. Needs `config:read` |
| `PUT /admin/organizations/{orgID}/scopes` | Declare or update one. Needs `organizations:write` |
| `DELETE /admin/organizations/{orgID}/scopes/{scope}` | Remove a declaration |
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
| `GET /admin/clients/{clientID}` | One client |
| `POST /admin/clients` | Register a client. `require_pkce` defaults to `true` for confidential clients as well as public ones; `false` is an explicit opt-out and is refused for a public client |
| `PATCH /admin/clients/{clientID}` | `enabled`, `require_pkce`, `may_exchange` and `exchange_audiences`. Only the fields sent are changed, and the response gives what was set. A public client cannot drop PKCE, and cannot be granted token exchange (`400 confidential_client_required`). `exchange_audiences` replaces the list of audiences the client may exchange tokens for besides itself; an entry with whitespace is `400 invalid_audience`. `post_logout_redirect_uris` (replaces the list), `frontchannel_logout_uri` (empty clears) and `frontchannel_logout_session_required` register sign-out, see [logout](logout.md#registering-a-clients-sign-out); a URI that breaks the redirect-URI rules is `400 invalid_logout_uri`. `access_token_ttl_s` (60 to 3600) and `refresh_token_ttl_s` (300 to 31536000) set the token lifetimes, as `signari client set-lifetimes` does; out of bounds is `400 invalid_client_setting` |
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

### Claim mappers

Which attribute becomes which claim, where, and for whom.

| | |
|---|---|
| `GET /admin/organizations/{orgID}/claim-mappers` | Everything this organisation releases. Needs `config:read` |
| `POST /admin/organizations/{orgID}/claim-mappers` | Release an attribute as a claim. Needs `organizations:write` |
| `DELETE /admin/organizations/{orgID}/claim-mappers/{mapperID}` | Stop releasing it |

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
