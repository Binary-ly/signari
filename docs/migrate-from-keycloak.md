# Migrating from Keycloak

## Introduction

When you move from Keycloak to Signari, you should not have to touch every
application that signs people in through it. People should keep their passwords,
and applications should keep their client secrets.

`signari import keycloak` reads a Keycloak realm export, and writes it into one
Signari organisation. A "realm" is Keycloak's word for an organisation. People keep
their password hashes, and applications keep their client IDs, secrets and redirect
URIs. So the move can be a Domain Name System (DNS) change, instead of a change to
every application.

You export the realm on the Keycloak host, then run the import from the command
line.

## Export and import a realm

Export the realm on the Keycloak host, then preview the import with `-dry-run`
before you run it:

```sh
# On the Keycloak host:
kc.sh export --realm your-realm --file realm.json

# Here — preview first, it writes nothing:
signari import keycloak -file realm.json -org <uuid> -dry-run
signari import keycloak -file realm.json -org <uuid>
```

A dry run is the import itself, run in a transaction that is rolled back. Its
report is therefore what the import would do: who already exists, which provider
links resolve, which groups would be renamed. Until October 2026 it counted every
person as created, and said nothing of what would be left behind.

## What comes across

People come across with their existing password hashes. Clients, which are
Keycloak's applications, come across with the secrets they already hold and their
redirect URIs.

The point of importing a secret, rather than issuing a new one, is that the
application does not have to be touched. Migration becomes a DNS change, instead of
a change to every downstream application.

The realm's other contents also come across:

| In the realm | Here |
|---|---|
| Groups, by path, and who is in them | Groups. A path becomes a name such as `/Engineering Team/Backend` → `Engineering-Team.Backend` (segments joined by `.`, other characters `-`), and each rename is listed |
| Realm roles a person holds | A group per role, `role.<name>`, so a policy can name who held it. Keycloak's own (`offline_access`, `uma_authorization`, `default-roles-*`) are left behind and listed apart |
| OTP (TOTP and HOTP) | The same seed, algorithm, digits and period, sealed under the person's key. A counter-based token's counter is carried as the last one used. Needs `SIGNARI_ROOT_KEY` |
| Passkeys | Saved under the relying party ID the realm states (`webAuthnPolicyRpId`, `webAuthnPolicyPasswordlessRpId`), each key checked as a COSE key, and the account takes the user handle Keycloak registered them under (see below). They work only if this deployment serves that same ID. A realm stating none used its host name, which the export does not record, so the passkeys are left behind |
| Links to an upstream provider | Kept, where a provider with the same slug as the realm's alias is registered here first. A person whose only way in is such a link is imported with no password |
| Attributes | Written where the organisation declares an attribute of that name |
| SAML clients | Service providers, with the HTTPS ACS URLs and the NameID format (`email`, `persistent`, `transient`), and each person's persistent NameID (see below) |

In this table, one-time passwords (OTP) are the codes from an authenticator: a
time-based one (TOTP) or a counter-based one (HOTP). SAML is Security Assertion
Markup Language, described in [SAML 2.0](saml.md).

**Everything else is named in the report** under `not carried`, with the reason.
The report names:

- Roles granted through a group.
- Composite roles' contents.
- Client roles.
- Attributes nobody declared.
- Links to providers not registered here.
- A client's implicit flow, direct access grants and protocol mappers.
- A SAML client's certificates and signing settings.

Keycloak's built-in clients (`account`, `admin-cli`, `broker` and the rest) are
left behind and listed apart.

A SAML client whose NameID format is `username` is skipped and named, not brought
across as another format. Keycloak sends the username in that format, and no format
here does. Every account at the service provider is keyed on the NameID. So another
value would point them at a subject the provider has never seen.

A client that states no format is skipped too. Keycloak sends such a client the
format its request asks for. When the request asks for none, Keycloak sends the
username. Until October 2026 such a client was imported as persistent.

## What applications know people by

An application keys its accounts on what the provider sends it. If that value
changes at cutover, the application meets every person as a stranger, and makes
them a second account. Three such values come across:

- **The subject.** Keycloak sends the person's ID as `sub`, and an account here
  sends its own ID. An imported person is given the realm's ID as theirs.
- **The passkey user handle.** An authenticator returns the handle a passkey was
  registered under. Both kinds of sign-in refuse a passkey whose handle is not the
  account's. Keycloak registers a passkey under the person's ID. An imported person
  with passkeys is given that handle.
- **The persistent NameID.** Keycloak keeps the NameID each SAML client knows a
  person by in the attribute `saml.persistent.name.id.for.<client>`, or
  `saml.persistent.name.id.for.*` for every client. Each one is kept for the
  service provider here that is sent persistent NameIDs.

Each of these is kept only when nobody here holds it. A person already here,
matched by address, keeps the ID they have. They take the handle only if none of
their passkeys here was registered under the handle they have. Changing it would
lock out those passkeys.

The report names every person whose subject, handle or NameID could not be kept,
with the reason and the new value. Their passkeys are then left behind, since
sign-in would refuse them, and they register again.

A person whose username already belongs to another account here, under a different
address, is skipped and named. Where either side has no address, they are taken to
be the same person. Both cases used to fail the whole import.

A second run duplicates nothing and resets nothing. An OTP credential held already,
whether imported before or enrolled since, is kept. Assigned again, a counter-based
token's counter would go back to the export's. The codes pressed since would then
work a second time.

A password credential whose `hashIterations` is above one million is **skipped and
named** with the count. The reason is that sign-in will not spend that much on one
attempt.
Such people sign in through recovery or delegated sign-in. Such a credential used
to be imported, and then refused at every attempt.

## PKCE is required of every imported client

Every client created here requires a Proof Key for Code Exchange
([PKCE](glossary.md#pkce)) challenge, imported ones included. The importer once
required it only of public clients. So every imported confidential client accepted
an authorization request without a challenge.

That is the one change an imported application may notice. A confidential
browser-flow client whose code sends no `code_challenge` is refused at its first
sign-in after cutover. The import report lists every confidential client this
applies to.

Check each one before you switch DNS, and opt out any that cannot send a challenge:

```sh
signari client set-pkce -client-id <id> -require-pkce=false
```

You can also send `PATCH /admin/clients/{id}` with `{"require_pkce": false}`. A
public client cannot opt out.

## Grants, and the bug that was fixed here (21 August 2026)

This section is the record of a bug in the importer, and of how it was fixed.

Keycloak calls the client credentials grant **"service accounts"**
(`serviceAccountsEnabled`). A client may have it alongside the browser flow, or on
its own.

The importer read that field off the realm export and dropped it. Every imported
client was written with `grant_types` hardcoded to `authorization_code` +
`refresh_token`. Two cases came out wrong, in opposite directions:

- **Both flows enabled.** The client was imported, and its browser sign-ins worked
  perfectly. Its machine-to-machine calls began failing `unauthorized_client` at
  cutover, with nothing in the migration report mentioning it. This is the
  dangerous half. The migration looks successful, because the part a human tests by
  hand is the part that still works. It is found by whichever batch job runs next,
  which may be a month later.
- **Service accounts only.** Skipped, and reported as *"not using the authorization
  code flow"*. That is true, and beside the point, because Signari implements the
  grant that client does use.

The importer had already stated the right principle, one comment above the bug. A
client *"created here in a shape that cannot work ... is worse than leaving it out
and saying so."*

It was applied to the clients left out, and not to the ones brought in.

Grants are now derived from the source client:

| Keycloak client | Imported grants |
|---|---|
| `standardFlowEnabled` | `authorization_code`, `refresh_token` |
| `serviceAccountsEnabled`, confidential | `client_credentials` |
| both | all three |
| `serviceAccountsEnabled` on a **public** client | no `client_credentials` |
| neither flow | skipped, and reported |

**A public client never receives `client_credentials`.** Keycloak does not permit
service accounts on one. A public client holds no secret to authenticate the grant
with. Importing it would create exactly the unusable shape the skip exists to
prevent.

The tests assert the negative cases as hard as the positive ones. An import that
*widens* a client's grants is a privilege escalation performed by the migration
tool. It happens on every client at once, at the moment an administrator is least
able to audit it. So `kc-browser`, which had no service account, must not come out
with one.

The tests caught each of these mutations:

```
CAUGHT   hardcode the grant list again (the state before this pass)
CAUGHT   give client_credentials to public clients too
CAUGHT   give every imported client client_credentials
```

## Names

`firstName` and `lastName` become the account's given name and surname, and
together its display name. They are released under the `profile` scope as
`given_name`, `family_name` and `name`, in the ID token and at userinfo. They are
also advertised in `claims_supported`.

A second import fills only names an account does not have, so a name changed after
the move is never put back. Until October 2026 the importer read both fields and
wrote neither, and no name was released at all.
