# Exporting a person's data

Everything Signari keeps about one person, as one JSON document. It answers a
request under a right of access or of portability, and it is the same document
however it is asked for:

| Who | How |
|---|---|
| The person | `/account/export`, linked from their account page: a recent sign-in, never an impersonation, and every channel the account has is told when a copy is downloaded |
| An operator | `signari export subject -subject-id <uuid> -out <file>`, which needs `SIGNARI_ROOT_KEY` and writes the file readable by its owner only |
| Automation | `GET /admin/subjects/{subjectID}/export` with a `subjects:export` token ([admin-tokens.md](admin-tokens.md)) |

Each one is recorded before the document leaves: `account.exported` for the
person, `admin.subject_exported` for an operator, with which way it went and
who. The record holds a row count, never the contents. Who was handed a
person's data is what an inquiry into a disclosure asks first.

## What is in it

```json
{
  "format": "signari-subject-export/1",
  "subject_id": "…",
  "exported_at": "2026-10-22T09:14:00Z",
  "tables": { "users": [ … ], "sessions": [ … ], "consents": [ … ], … },
  "attributes": [ { "name": "home_address", "value": "…", "readable": true } ],
  "withheld": { "password_credentials": ["hash"], "sessions": ["cookie_hash", "ip_hash"], … }
}
```

`tables` holds the person's rows from every table that keeps them, by table, as
the database holds them: the account, every sign-in method, the sessions and the
applications each one reached, what each application was given, consents, the
profile, group memberships and permissions, provisioning links, and the audit
entries about them. Every table is present even when it holds nothing of theirs,
so an empty list says there is nothing there rather than that nobody looked.

`attributes` are their attribute values. A personal attribute is sealed under the
person's own key, so the document unseals it; `readable: false` means the key has
been destroyed by an erasure.

## What is withheld, and why

A credential appears as being there, never as its value. The hash of a password,
of a session cookie, of a recovery or one-time code, a sealed authenticator-app
secret and the wrapped key itself are left out, and `withheld` names each column
left out of each table. That a password is set, when it was changed and that two
recovery codes remain are all still there. What is not there is anything that
could be used to sign in as them, or to attack their password offline, from
wherever the file ends up.

The rule is by type rather than by list: every binary column is withheld except
public key material (a passkey's credential id, public key and authenticator
model, and the account's WebAuthn user handle). A text column that holds a
credential, such as a password hash, is withheld by name. A test fails when a
column whose name sounds like a credential is neither withheld nor explained.

## Rows about the person, not by them

Some rows name a person as the one who acted: the invitations they sent, the
memberships and permissions they granted, the sessions of someone they
impersonated, the audit entries for what they did to other accounts. Those rows
belong to the people they are about, and an invitation carries the invitee's
address. A person's export does not include them. A person's own entries in the
trail, the ones about their account, are included.

## It cannot quietly miss a table

The list of places the export looks is held to the schema by a test, which
derives every place a person's rows can be kept: every foreign key to the
accounts table, every table whose rows are deleted along with one of those, and
every column named for a person that has no foreign key at all. A new table that
keeps a person's rows fails the build until the export takes them from it, or
says the column names the one who acted.

See [erasure.md](erasure.md) for the other half: destroying what this exports.
