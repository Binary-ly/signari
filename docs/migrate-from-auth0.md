# Migrating from Auth0

```sh
# Export the users from Auth0 as JSON: Import/Export Users in its dashboard,
# or its Management API's POST /jobs/users-exports with "format": "json".

# Here: a migration source that checks each person's password with Auth0 at
# their first sign-in (see password-migration.md). Then preview first, it
# writes nothing:
signari import auth0 -file tenant.json -org <uuid> -dry-run
signari import auth0 -file tenant.json -org <uuid>
```

A dry run is the import itself, run in a transaction that is rolled back, so its
report is what the import would do. Run it again after registering a provider or
declaring an attribute. It duplicates nothing.

## No password comes across

Auth0's bulk export holds no password. Its hashes come only through a support
request, as a PGP-encrypted file whose layout Auth0 does not document, so this
does not read one. That decides how people arrive. A person here with no
password and no way to sign in is refused, not created, because an account
nobody can use is worse than one that was refused. So a person comes across one
of these ways:

- **Checked at their first sign-in.** Where the organisation has a
  [migration source](password-migration.md), everybody comes in pending. The
  first time each signs in here, the source checks the password they type
  against Auth0, and when Auth0 accepts it, a hash is kept here. Nobody has to
  choose a new password. The report says whether the source is enabled yet:
  test it with `signari migration-source test` before you enable it.
- **An identity the export names.** An Auth0 user can be linked to a social or
  enterprise connection. Where a provider is registered here under the slug the
  connection's name makes, the person is linked to it by their identifier there.
  The slug is lower case, with other characters as hyphens: `Google Workspace`
  becomes `google-workspace`.
- **Auth0 itself, with `-via`.** Every person who is not blocked is linked to the
  provider you registered for Auth0, by their Auth0 `user_id`. They sign in
  through Auth0 while the move lasts. To stop, each sets a password here through
  account recovery, or registers a passkey from their account page.

Anyone with none of these is skipped and named. **Check one link before relying
on them.** A link matches only if Auth0 sends the person's `user_id` as the ID
token's `sub`. That is Auth0's to say, and it was not tested here. Sign in once,
as one imported person, through the provider. A link that does not match finds
nobody. Sign-in never matches an account by address, so a wrong link refuses that
person; it never lets anyone into someone else's account.

## What comes across

| In Auth0 | Here |
|---|---|
| People | Their address and whether it was verified, username, given and family name, and `name` as the display name. Blocked people are skipped and named |
| Identities | Links, as above |
| `user_metadata` | Each text value, where the organisation declares an attribute of that name. Needs `SIGNARI_ROOT_KEY` |

## What does not, and why

- **Passwords**, as above.
- **`app_metadata`.** It decided what a person could do there. Nothing is granted
  here by having had it: grant groups instead. The report counts the people who
  had any.
- **Second factors.** The export holds no secret of a person's. They enrol again.
- **The subject.** An account here has an id of its own, a UUID, which is what
  applications are sent as `sub`. An application that keyed its accounts on the
  identifier Auth0 gave a person meets them as a stranger until it is told the
  new one. The report says how many people this applies to.
- A nickname, picture or phone number, and any `user_metadata` value that is not
  text. Each is counted in the report.
- **The CSV export.** It cannot hold the identities that link a person, or
  metadata as objects, so it is refused. Export as JSON.
