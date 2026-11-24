# Migrating from Okta

## Introduction

When you move from Okta to Signari, people should be able to sign in on the first
day without choosing a new password. Okta has no export file, and its users API
does not give out passwords. So each person has to come across with some other way
to sign in.

`signari import okta` reads the people from a file you save from Okta's users
API, and creates them in one Signari organisation. Their password can be checked
with Okta at their first sign-in, or they can sign in through Okta while the move
lasts.

You run the import from the command line, after setting up a [migration
source](password-migration.md) or a provider.

## Save the people and import them

List the people with Okta's users API into one file, set up a migration source,
then preview the import before you run it:

```sh
# Okta has no export file: list the people with its users API,
# GET /api/v1/users, and save the pages into one file, one after another.

# Here: a migration source that checks each person's password with Okta at
# their first sign-in (see password-migration.md). Then preview first, it
# writes nothing:
signari import okta -file okta-users.json -org <uuid> -dry-run
signari import okta -file okta-users.json -org <uuid>
```

The file holds User objects as the users API lists them: the pages one after
another, or one User to a line.

A dry run is the import itself, run in a transaction that is rolled back. Run it
again whenever you like. It duplicates nothing.

## No password comes across

Okta answers a password as a bare `{}`, which says that one exists and nothing
more. A person here with no password and no way to sign in is refused, not
created. An account nobody can use is worse than one that was refused. So a person
comes across in one of two ways:

- **Checked at their first sign-in.** Where the organisation has a [migration
  source](password-migration.md), everybody comes in "pending": waiting for their
  first sign-in. The first time each signs in here, the source checks the password
  they type against Okta. When Okta accepts it, a hash is kept here. Nobody has to
  choose a new password. The report says whether the source is enabled yet: test it
  with `signari migration-source test` before you enable it.
- **Okta itself, with `-via`.** Everybody is linked to the provider you registered
  for Okta (see [federated sign-in providers](social-login.md)), by their Okta
  `id`. They sign in through Okta while the move lasts. To stop, each sets a
  password here through account recovery, or registers a passkey from their
  account page.

With neither, everybody is skipped and named.

**Check one link before relying on them.** A link matches only if Okta sends the
person's `id` as the ID token's `sub`. That is Okta's to say, and it was not tested
here. Sign in once, as one imported person, through the provider.

A link that does not match finds nobody. Sign-in never matches an account by
address. So a wrong link refuses that person, and it never lets anyone into someone
else's account.

## What comes across

Each field of a User becomes this in Signari:

| In Okta | Here |
|---|---|
| `profile.login` | The username |
| `profile.email` | The address. Nothing in a User says it was confirmed, so it comes across unverified |
| `profile.firstName`, `lastName`, `displayName` | The names |
| `status` | `ACTIVE`, `PASSWORD_EXPIRED`, `RECOVERY`, `LOCKED_OUT`, `STAGED` and `PROVISIONED` people come across. `SUSPENDED` and `DEPROVISIONED` people are skipped and named, since importing them would turn on an account somebody turned off |

## What does not, and why

Some things cannot come across:

- **Passwords**, as above.
- **People who sign in against a directory or another provider there**. Their
  `credentials.provider` is Active Directory, [Lightweight Directory Access
  Protocol (LDAP)](glossary.md#ldap), a federation or a social provider. The
  report counts them by provider. Connect the directory here with
  `signari dir add`, or register the provider with `signari idp add`.
- **The subject.** An account here has an ID of its own, which is what
  applications are sent as `sub`. An application that keyed its accounts on the
  `id` Okta gave a person meets them as a stranger, until it is told the new one.
- **Other profile fields**, such as `mobilePhone`, `title` or a custom one. Each is
  counted in the report by name.
- **Groups, factors and applications.** The users API does not list them with a
  person.
