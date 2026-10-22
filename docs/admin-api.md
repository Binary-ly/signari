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
row the same way.

### Configuration

| | |
|---|---|
| `GET /admin/config-version` | The current version. The read half of the conditional-write protocol |
| `GET /admin/openapi.json` | An OpenAPI 3.1 description of this API, **generated from the router**. Unauthenticated |

**The OpenAPI document is derived, not written.** It cannot describe a route that
is not registered or omit one that is, and each operation carries the scope the
server actually enforces — taken from the same `auth(scope, …)` wrapper that
enforces it, so a client generated from it calls the routes that exist, with the
scopes they need, rather than those somebody last remembered to document. It
knows nothing of the bodies: request and response *schemas* are not in the
document, because reflecting over the Go structs would describe the JSON tags
rather than the meaning, so a generated client has untyped bodies and those stay
in this page.

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

### Organisations

| | |
|---|---|
| `POST /admin/organizations` | Provision a tenant. `slug`, `display_name`, and `instance_id` — the last required only when the deployment has more than one instance. Needs `organizations:write` **and an unscoped token** |
| `GET /admin/organizations` | Every organisation, with its `status`, for an unscoped token; its own for a scoped one. `config:read` |
| `GET /admin/organizations/{orgID}` | One organisation and its `status`. `config:read` |
| `PATCH /admin/organizations/{orgID}` | `{"status": "suspended"}` or `"active"`. Suspended, the organisation is refused at every entry point from the next request: sign-in by any method, the sessions it has, its clients at every OAuth and OIDC endpoint, its tokens at userinfo and introspection, LDAP binds, RADIUS, SCIM provisioning, its outposts (AuthZEN and LDAP), sign-up, recovery and passkey links, and its own admin tokens, which get 403 `organisation_suspended`. **Nothing is ended**: reactivated, a session or grant with time left resumes, so end them as well if that is what you mean. Audited `admin.organization_suspended` / `admin.organization_reactivated`. Needs `organizations:write` **and an unscoped token**, since a tenant that could lift its own suspension would not be suspended; honours `If-Match`. `signari instance org-status` does the same |

**Only an unscoped token may create an organisation.** A token scoped to one
organisation is refused, because a tenant that can provision tenants has escaped
the isolation the rest of the product enforces: it could create a sibling and
then act on it. This reuses the same `MayActOn` check every other write uses
rather than adding a second boundary that has to be kept in step.

**There is no `DELETE`,** and that is a decision. Every user, client, session,
token and audit event in a deployment hangs off an organisation, so a one-call
tenant deletion is irreversible destruction of everything a customer has,
reachable by one mistyped identifier. Removing the data is a deliberate operation
done with the database in front of you. Suspending a tenant is not built yet:
`organizations.status` exists, nothing sets it and nothing reads it, so stopping
a tenant today means disabling its clients and deactivating its people. This
page said that setting `status` to `suspended` stopped the tenant working.

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
| `PATCH /admin/clients/{clientID}` | `enabled`, `require_pkce`, `may_exchange` and `exchange_audiences`. Only the fields sent are changed, and the response gives what was set. `enabled: false` holds from the next request: the client's outstanding access tokens introspect as inactive and are refused by userinfo, token exchange, transaction tokens and the credential endpoint. A resource server that checks only the signature accepts them until they expire, at most the client's access-token lifetime. A public client cannot drop PKCE, and cannot be granted token exchange (`400 confidential_client_required`). `exchange_audiences` replaces the list of audiences the client may exchange tokens for besides itself; an entry with whitespace is `400 invalid_audience`. `post_logout_redirect_uris` (replaces the list), `frontchannel_logout_uri` (empty clears) and `frontchannel_logout_session_required` register sign-out, see [logout](logout.md#registering-a-clients-sign-out); a URI that breaks the redirect-URI rules is `400 invalid_logout_uri`. `access_token_ttl_s` (60 to 3600) and `refresh_token_ttl_s` (300 to 31536000) set the token lifetimes, as `signari client set-lifetimes` does, and `id_token_signed_response_alg` (ES256, RS256, PS256, EdDSA) what signs the client's tokens, as `signari client set-alg` does, refused unless the instance holds an active key of it; `require_pushed_authorization_requests` and `first_party` are the switches `client set-par` and `client set-first-party` set; `issuer_alias` pins the client to a live alias of its instance (`""` clears), as `client set-issuer-alias` does; `minimum_acr` (`"1"` to `"4"`: a single factor, multi-factor, multi-factor with a passkey or security key, or with a key bound to its device) is the weakest authentication the client accepts, as `client set-acr` sets it; `consent_lifetime_s` (3600 to 315360000, or 0 for never) is how long a person's consent to it lasts before they are asked again, as `client set-lifetimes -consent-ttl` sets it; out of bounds is `400 invalid_client_setting` |
| `DELETE /admin/clients/{clientID}` | Remove the client and everything issued under it. Real deletion, not a flag (ADR-005): every code, token, refresh family, consent, pushed request and device authorisation cascades with it. The audit trail keeps its records — `audit_events.client_id` has no foreign key, so the history of a client outlives the client. Returns `refresh_families_revoked`: the refresh token families that could still be redeemed and now cannot. Access tokens are signed JWTs recorded nowhere, so there is no count of them to give |
| `POST /admin/clients/{clientID}/rotate-secret` | New secret, shown once. The previous one stops working immediately |

### Users

| | |
|---|---|
| `GET /admin/users` | List, paged |
| `GET /admin/users/{userID}` | One user |
| `POST /admin/users` | Create |
| `PATCH /admin/users/{userID}` | Activate (which approves a self-sign-up waiting, `pending`, for approval and tells the person they can sign in; audited with `approved: true`), deactivate, set a password, require a change, and edit identity: `email`, `username`, `display_name`, `given_name`, `surname`. An empty string clears a field; both identifiers cannot be cleared at once (400 `no_identifier_left`), and a taken address or name is 409 `already_exists`. A password set, or an address changed, is told to the person on every channel, queued with the change; an address change goes to the old address too, naming neither |
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
