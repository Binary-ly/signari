# Migrating from Microsoft Entra ID

## Introduction

When you move from Microsoft Entra ID to Signari, people should be able to sign in
on the first day without choosing a new password. Entra ID exports no passwords,
so each person has to come across with some other way to sign in.

`signari import entra` reads a list of the people in Entra ID, and creates them in
one Signari organisation. Each account keeps the person's object ID as its own ID, so an
application that knew them by it keeps knowing them. People sign in through Entra
ID while the move lasts, or have their password checked at their first sign-in.

You run the import from the command line, after registering Entra ID as a provider
or setting up a [migration source](password-migration.md).

## Download the people and import them

Download the list of people from Entra ID, register Entra ID as a provider, then
preview the import before you run it:

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

In this example, Entra ID is registered as an [OpenID Connect
(OIDC)](glossary.md#oidc) provider, as [federated sign-in
providers](social-login.md) describes.

Two files are read:

- the comma-separated values (CSV) file that the first comment above downloads,
  whose columns include `userPrincipalName`, `objectId` and `accountEnabled`;
- Graph's `user` resources as JSON, either a list of them or an object holding the
  list under `value`.

The preview download takes its columns from whatever the portal's list shows. So it
is read only when those three columns are among them.

Graph sends `accountEnabled` only when asked for. A listing without it is refused,
so that nobody disabled there is enabled here.

A dry run is the import itself, run in a transaction that is rolled back.

## No password comes across

Entra ID exports none. A person here with no password and no way to sign in is
refused, not created. An account nobody can use is worse than one that was
refused. So a person comes across in one of two ways:

- **Entra ID itself, with `-via`.** Everybody is linked to the provider `-via`
  names, by their object ID. They sign in through Entra ID while the move lasts.
  To stop, each sets a password here through account recovery, or registers a
  passkey from their account page.
- **Checked at their first sign-in.** Where the organisation has a [migration
  source](password-migration.md), everybody comes in "pending": waiting for their
  first sign-in. The source checks the password each one types the first time they
  sign in here, and keeps a hash when it is accepted. Whatever the source asks has
  to accept an Entra ID password. A service of your own behind the
  `password_verify` hook can be that. The report says whether the source is
  enabled yet.

With neither, everybody is skipped and named.

**Check one link before relying on them.** A link matches only when the person's
object ID reaches the provider here as the ID token's `sub`. Which claim carries it is
Microsoft's to say, and it was not tested here. Sign in once, as one imported
person, through the provider.

A link that does not match finds nobody. Sign-in never matches an account by
address. So a wrong link refuses that person, and it never lets anyone into someone
else's account.

## What comes across

Each field of a person's record becomes this in Signari:

| In Entra ID | Here |
|---|---|
| `objectId` / `id` | The account's own id. An object ID is a UUID, which an id here is, so an application that knew a person by it keeps knowing them |
| `userPrincipalName` | The username |
| `mail` | The address, unverified: nothing in the export says it was confirmed |
| `givenName`, `surname`, `displayName` | The names |
| `accountEnabled` | Disabled people are skipped and named |
| `userType` | Guests come across like members, as people of this organisation. The report counts them |

An object ID is a universally unique identifier (UUID), the same kind of ID an
account here has.

## What does not, and why

Some things cannot come across:

- **Passwords**, as above.
- **Other columns and properties**, such as `jobTitle`, `department` or
  `officeLocation`. Each is counted in the report by name.
- **Groups, roles and application assignments.** A download of the people does not
  hold them.
