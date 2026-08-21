# Migrating from authentik

```sh
# On the authentik host:
ak dumpdata authentik_core.User authentik_core.Group > authentik.json

# Here — preview first, it writes nothing:
signari import authentik -file authentik.json -org <org-uuid>
signari import authentik -file authentik.json -org <org-uuid> -apply
```

**Nobody resets a password.** People sign in with the password they already had.

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

  users created : 2
  groups        : 2

  skipped (2):
    gone@authentik.test (inactive in authentik)
    sso@authentik.test (password format "unusable (federated or never set)"
      cannot be verified here; they must use recovery or delegated sign-in)
```

"We imported 400 users" means nothing if 380 carry a format nothing here can
check. The census is the number that decides whether a cutover needs a password
reset, so it prints before the totals.

The verifiable/not verdict comes from `passwords.CanVerify`, not from a second
list in the importer. A first version kept its own prefixes and got one wrong —
it tested for `argon2` where the stored form is `$argon2id$`, so a perfectly
importable hash was reported as unrecognised. A test now requires the two to
agree.

## What is deliberately not imported

- **Inactive users**, named in the skip list. Importing them as active would
  silently re-enable accounts somebody turned off on purpose.
- **Users with no usable password** (`!`, Django's marker for federated-only
  accounts). Named rather than imported without a credential: an account nobody
  can sign in to is worse than one that was refused out loud.
- Everything that is not a user or a group. A dumpdata file contains tokens,
  flows and stages; those are authentik's model, not ours.
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

Group membership transfers too: groups are read in a first pass, because a user
record references them by primary key and a single pass would resolve only the
groups that happened to appear earlier in the file.

## Honesty about what this was tested against

Built against the documented `dumpdata` shape and a synthetic export containing
real Django PBKDF2 hashes. **It has not yet been run against an export from a
live authentik deployment.** A version that renames a field will show users in
the skip list rather than importing them without a credential, and the dry run
prints exactly what was parsed — so the first real run is informative rather than
destructive. Run it without `-apply` first.

## What comes after the users

`import authentik` moves people and groups. Applications still need registering,
because an OAuth client's redirect URIs and secrets are a decision rather than a
translation — and `client create` accepts a verbatim `client_id` and secret, so
downstream applications need no change. See the issuer-aliasing note in
`roadmap-total-parity.md`.
