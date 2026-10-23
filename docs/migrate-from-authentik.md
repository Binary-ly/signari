# Migrating from authentik

```sh
# On the authentik host:
ak dumpdata authentik_core.user authentik_core.group authentik_core.usergroup \
  authentik_core.groupparentagenode authentik_core.source authentik_core.usersourceconnection \
  authentik_core.provider authentik_core.application authentik_providers_oauth2.oauth2provider \
  authentik_providers_saml.samlprovider authentik_stages_authenticator_totp.totpdevice \
  authentik_stages_authenticator_webauthn.webauthndevice > authentik.json
# and, in authentik's database, its installation ID:
#   SELECT id FROM authentik_install_id ORDER BY id LIMIT 1;

# Here — preview first, it writes nothing:
signari import authentik -file authentik.json -org <org-uuid> -install-id <id>
signari import authentik -file authentik.json -org <org-uuid> -install-id <id> -apply
```

**Nobody resets a password.** People sign in with the password they already had.

A version of authentik that lacks one of those models keeps its data in an
older shape, and `dumpdata` refuses to name the model. Leave it out of the
command. The older shapes are read too: a user's `ak_groups` list, a group's
single `parent`, and redirect URIs kept as newline-separated text.

The preview is the import itself, run in a transaction that is rolled back. Its
report is therefore what the import would do: who already exists, which links
resolve, which groups are renamed. It used to count every user as created.

## What comes across

| In authentik | Here |
|---|---|
| Users | People, with their password hash, display name and UUID (see below). Inactive users are skipped. Service accounts are skipped, since they sign in with tokens, and outpost accounts are left behind as authentik's own |
| Groups and who is in them | Groups. A name becomes a name such as `Domain Admins` → `Domain-Admins`, and each rename is listed. Groups here do not nest, so the members of a group are also made members of every group above it, as authentik counts them |
| TOTP devices | The same seed, digits and period, HMAC-SHA1 as authentik uses, with the last step used, sealed under the person's key. One per person; an unconfirmed device is left behind. Needs `SIGNARI_ROOT_KEY` |
| WebAuthn devices | Saved under the relying party ID each was registered with, each key checked as a COSE key. Needs `-install-id` (see below) and a deployment that serves the same relying party ID |
| Links to a source | Kept, where a provider with the same slug as the source is registered here first. A person whose only way in is such a link is imported with no password |
| Attributes | Written where the organisation declares an attribute of that name, when the value is text |
| OAuth2 providers | Clients with the client ID and secret they hold, named after their application, with the grants this server implements, the strict redirect URIs and the post-logout ones |
| SAML providers | Service providers, keyed by the audience, with the HTTPS ACS URL, the NameID format and each person's persistent NameID (see below) |

**Everything else is named in the report** under `not carried`, with the
reason. That includes a group's superuser flag and attributes, links to sources
not registered here, attributes nobody declared, property mappings, the
implicit, hybrid and password grants, regular-expression redirect URIs, logout
URIs and SAML signing settings, and providers of other kinds. Every record of a
model the import does not read is counted by model.

A SAML provider is skipped and named when it states no audience, because the
audience is the entity ID that a request is matched by. It is also skipped when
a property mapping makes its NameID, or when its NameID comes from a directory
attribute. Brought across with another NameID, every account at the service
provider would be keyed on a subject it has never seen.

## What applications know people by

An application keys its accounts on what the provider sends it. If that value
changes at cutover, the application meets every person as a stranger.

- **The subject.** An account here sends its id as `sub`, and an imported person
  is given their authentik UUID as that id. A provider whose subject mode is
  `user_uuid` therefore keeps sending the same subject. authentik's default
  mode, `hashed_user_id`, and the modes based on the username, email or UPN
  cannot be sent from here. The report names each client that used one of them,
  so the application can be re-keyed or re-linked before cutover.
- **The passkey user handle.** authentik registers every passkey under a value
  it derives from the user's id and its installation ID, and both kinds of
  sign-in refuse a passkey whose handle is not the account's. With `-install-id`,
  an imported person is given that handle. Without it, their passkeys are left
  behind and named, since sign-in would refuse them.
- **The persistent NameID.** authentik makes this from the same value, so with
  `-install-id` each person's NameID is kept for every service provider that is
  sent persistent NameIDs. Without it, the report says so for each provider.

Each of these is kept only when nobody here holds it. A person already here,
matched by address, keeps the id they have. They take the handle only if none
of their passkeys here was registered under the handle they have. The report
names every person whose subject, handle or NameID could not be kept.

With authentik's tenants enabled, a non-default tenant derives these values from
the tenant's ID, not from the installation ID. Pass that tenant's ID instead.

A provider with no signing key signs its ID tokens with HS256 under the client
secret. Here they are signed with ES256 and published at the JWKS URI. The report
names each such client, because its application must accept that.

## Why the passwords come across

authentik is a Django application, and its settings do **not** set
`PASSWORD_HASHERS` — so Django's defaults apply, and the first of those, the one
used whenever a password is set, is `PBKDF2PasswordHasher`:

```
pbkdf2_sha256$<iterations>$<salt>$<base64 hash>
```

`internal/passwords` has verified that format from the beginning, because it is
common to a great deal of Python software. So an imported user's password
verifies as-is on their first sign-in and is replaced with Argon2id **in the same
transaction**. The foreign hash is transitional, never permanent.

That claim is asserted, not assumed: `TestTheHashFormatAuthentikStoresIsVerifiableHere`
builds a hash exactly the way Django does, verifies it through the real hasher,
and fails if the format ever stops being importable.

## Why a dumpdata file and not the API

authentik's REST API never returns password hashes. Django does not expose them,
and it is right not to. `dumpdata` is Django's own documented management command
and the portable export that does include them.

## The census comes first

```
  password formats found
    pbkdf2_sha256, Django default (verifiable)     3
    unusable (federated or never set)              1

  users:   2 created, 0 updated, 2 skipped
  ...
  skipped user:   gone@authentik.test (inactive in authentik)
  skipped user:   sso@authentik.test (password format "unusable (federated or
    never set)" cannot be verified here, and no link to a source registered
    here; they must use recovery or delegated sign-in)
```

"We imported 400 users" means nothing if 380 carry a format nothing here can
check. The census is the number that decides whether a cutover needs a password
reset, so it prints before the totals.

The verifiable/not verdict comes from `passwords.CanVerify`, not from a second
list in the importer. A first version kept its own prefixes and got one wrong —
it tested for `argon2` where the stored form is `$argon2id$`, so a perfectly
importable hash was reported as unrecognised. A test now requires the two to
agree.

"Verifiable" also means affordable. A hash whose own parameters cost more than
sign-in will spend is skipped and named, with the parameter that is too high:

- more than 10 million PBKDF2 iterations;
- 2^20 phpass or Drupal 7 rounds;
- bcrypt cost 15;
- a million SHA-crypt rounds;
- an Argon2id or scrypt hash needing more memory than the 512 MiB the process
  allows for all verifications together, or an imported scrypt hash needing
  more than 256 MiB.

Sign-in refuses the same hash, before doing any work, through the same check.
The importer used to ask only whether the format was known, so such an account
was imported and then refused at every attempt.

## What is deliberately not imported

- **Inactive users**, named in the skip list. Importing them as active would
  silently re-enable accounts somebody turned off on purpose.
- **Users with no usable password** (`!`, Django's marker for federated-only
  accounts) and no link to a source registered here. Named rather than imported
  without a credential: an account nobody can sign in to is worse than one that
  was refused out loud.
- Tokens, flows, stages, policies and the rest of authentik's own model. Their
  records are counted in the report by model.
- **`is_superuser` on a group.** Groups come across; the flag does not, because
  there is nothing here for it to mean — Signari has no group-conferred
  superuser. Capabilities attach to a group individually (see
  `0070_impersonation.sql`: *"A capability on a group rather than a role
  system"*), so there is no single switch that reproduces what authentik's flag
  did.

  Dropping it **fails closed** — an authentik admin group arrives as an ordinary
  group and nobody gains privilege by being migrated. That is the safe direction
  and it is deliberate, but it is worth stating out loud rather than leaving to
  be discovered: **after a migration, nobody is an administrator by virtue of
  their old group membership.** Grant whatever capabilities those groups need,
  explicitly, before decommissioning the authentik instance you would otherwise
  have to go back to in order to find out what they were.

## Migration state, and a bug that was fixed here

Imported users land as `migration_state = 'pending'` with `is_current = false` on
the credential. That is what routes them through the migration path rather than
treating a Django hash as a current one.

When the rehash happens, `migration_state` becomes `complete` and `migrated_at`
is stamped. That did not used to happen: `CompleteMigration` only runs on the
**delegated** sign-in path, so a hash-imported user stayed `pending` for ever,
however many times they signed in — and a "% migrated" cutover dashboard would
have read zero on a finished migration.

`migration_source_id` stays NULL, accurately: there was no delegated source, the
hash came across in an export.

Verified end to end:

```
import                      -> migration_state=pending, algorithm=django-pbkdf2
sign in with the old password -> 200
                            -> migration_state=complete, algorithm=argon2id
sign in again               -> 200, now against Argon2id
wrong password              -> "Incorrect username or password."
a user who never signs in   -> still pending, still the Django hash
```

Group membership transfers too. The whole file is read before any person's
groups are resolved, because records reference each other by primary key in no
particular order.

## Honesty about what this was tested against

Built against authentik's models as of its source at the time of writing, and a
synthetic export holding real Django PBKDF2 hashes, a TOTP device and a passkey.
**It has not yet been run against an export from a live authentik deployment.**
A version that renames a field will show users in the skip list rather than
importing them without a credential, and a record that does not parse is counted
in the report. The preview prints exactly what the import would do, so the first
real run is informative rather than destructive. Run it without `-apply` first.

## Issuer aliasing, for the applications you cannot reconfigure

A relying party verifies the `iss` claim it was configured with. Pointing DNS at
Signari changes that string, and every such application breaks at once.

A client may instead carry an **issuer alias**: a legacy issuer this deployment
also claims. Its tokens are minted under that old value rather than under the
deployment's own issuer, so the application moves with a DNS change instead of a
code change. Signari's own userinfo and introspection accept both, and the alias
is validated at write time by a database trigger against the instance's
registered aliases — a value that reaches the token path has already been proven
to be one this deployment legitimately claims.

```
signari instance add-alias -alias https://auth.example.com/application/o/wiki -retire-after 2026-12-31
signari client set-issuer-alias -client-id wiki -alias https://auth.example.com/application/o/wiki
signari instance aliases
signari instance retire-alias -alias https://auth.example.com/application/o/wiki
```

It is for cutover, not for permanent multi-tenancy, so give an alias a
`-retire-after`. Aliases are read per request: one registered is accepted from
the next request, and one past its retirement is refused from the next, with
pinned clients minted under the deployment's own issuer from then on.
