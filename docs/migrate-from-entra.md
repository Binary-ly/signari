# Migrating from Microsoft Entra ID

```sh
# Either: Users > All users > Download users in the Microsoft Entra admin
# center, which gives a CSV.
# Or: list the users with Microsoft Graph, naming accountEnabled in $select,
# and save the JSON.

# Here: register Entra ID as an OIDC provider (see social-login.md), with
# sign-up off, under a slug of your choosing, say "entra", or set up a
# migration source (see password-migration.md). Then preview first, it writes
# nothing:
signari import entra -file users.csv -org <uuid> -via entra -dry-run
signari import entra -file users.csv -org <uuid> -via entra
```

Two files are read: the admin center's **Download users** CSV, whose columns
include `userPrincipalName`, `objectId` and `accountEnabled`, and Graph's user
resources as JSON, either a list of them or an object holding the list under
`value`. The preview download takes its columns from whatever the user list
shows, so it is read only when those three columns are among them. Graph sends
`accountEnabled` only when asked for. A listing without it is refused, so that
nobody disabled there is enabled here. A dry run is the import itself, run in a
transaction that is rolled back.

## No password comes across

Entra ID exports none. A person here with no password and no way to sign in is
refused, not created, because an account nobody can use is worse than one that
was refused. So a person comes across one of two ways:

- **Entra ID itself, with `-via`.** Everybody is linked to the provider `-via`
  names, by their object ID. They sign in through Entra ID while the move lasts.
  To stop, each sets a password here through account recovery, or registers a
  passkey from their account page.
- **Checked at their first sign-in.** Where the organisation has a
  [migration source](password-migration.md), everybody comes in pending, and the
  source checks the password each one types the first time they sign in here,
  keeping a hash when it is accepted. Whatever the source asks has to accept an
  Entra ID password; a service of your own behind the `password_verify` hook can
  be that. The report says whether the source is enabled yet.

With neither, everybody is skipped and named. **Check one link before relying
on them.** A link matches only if the provider
here is sent the person's object ID as the ID token's `sub`. Which claim carries
it is Microsoft's to say, and it was not tested here. Sign in once, as one
imported person, through the provider. A link that does not match finds nobody.
Sign-in never matches an account by address, so a wrong link refuses that
person; it never lets anyone into someone else's account.

## What comes across

| In Entra ID | Here |
|---|---|
| `objectId` / `id` | The account's own id. An object ID is a UUID, which an id here is, so an application that knew a person by it keeps knowing them |
| `userPrincipalName` | The username |
| `mail` | The address, unverified: nothing in the export says it was confirmed |
| `givenName`, `surname`, `displayName` | The names |
| `accountEnabled` | Disabled people are skipped and named |
| `userType` | Guests come across like members, as people of this organisation. The report counts them |

## What does not, and why

- **Passwords**, as above.
- Every other column or property, such as `jobTitle`, `department` or
  `officeLocation`. Each is counted in the report by name.
- Groups, roles and app assignments. A user download does not hold them.
