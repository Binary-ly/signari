# Migrating from Keycloak

```sh
# On the Keycloak host:
kc.sh export --realm your-realm --file realm.json

# Here — preview first, it writes nothing:
signari import keycloak -file realm.json -org <uuid> -dry-run
signari import keycloak -file realm.json -org <uuid>
```

A dry run is the import itself, run in a transaction that is rolled back. Its
report is therefore what the import would do: who already exists, which
provider links resolve, which groups would be renamed. Until October 2026 it
counted every user as created and said nothing of what would be left behind.

## What comes across

Users, their existing password hashes, clients with the secrets they already
hold, and redirect URIs. The point of importing a secret rather than issuing a
new one is that the application does not have to be touched: migration becomes a
DNS change instead of a change to every downstream app.

The realm's other contents also come across:

| In the realm | Here |
|---|---|
| Groups, by path, and who is in them | Groups. A path becomes a name such as `/Engineering Team/Backend` → `Engineering-Team.Backend` (segments joined by `.`, other characters `-`), and each rename is listed |
| Realm roles a person holds | A group per role, `role.<name>`, so a policy can name who held it. Keycloak's own (`offline_access`, `uma_authorization`, `default-roles-*`) are left behind and listed apart |
| OTP (TOTP and HOTP) | The same seed, algorithm, digits and period, sealed under the person's key. A counter-based token's counter is carried as the last one used. Needs `SIGNARI_ROOT_KEY` |
| Passkeys | Saved under the relying party ID the realm states (`webAuthnPolicyRpId`, `webAuthnPolicyPasswordlessRpId`), each key checked as a COSE key. They work only if this deployment serves that same ID. A realm stating none used its host name, which the export does not record, so the passkeys are left behind |
| Links to an upstream provider | Kept, where a provider with the same slug as the realm's alias is registered here first. A person whose only way in is such a link is imported with no password |
| Attributes | Written where the organisation declares an attribute of that name |
| SAML clients | Service providers, with the HTTPS ACS URLs and the NameID format (`email`, `persistent`, `transient`) |

**Everything else is named in the report** under `not carried`, with the
reason: roles granted through a group, composite roles' contents, client roles,
attributes nobody declared, links to providers not registered here, a client's
implicit flow, direct access grants and protocol mappers, a SAML client's
certificates and signing settings. Keycloak's built-in clients (`account`,
`admin-cli`, `broker` and the rest) are left behind and listed apart.

A SAML client whose NameID format is `username` is skipped and named, not
brought across as another format. Keycloak sends the username in that format,
and no format here does. Every account at the service provider is keyed on the
NameID, so another value would point them at a subject the provider has never
seen.

A person whose username already belongs to another account here, under a
different address, is skipped and named. Where either side has no address,
they are taken to be the same person. Both cases used to fail the whole import.

A second run duplicates nothing and resets nothing. An OTP credential held
already, whether imported before or enrolled since, is kept. Assigned again, a
counter-based token's counter would go back to the export's, and the codes
pressed since would work a second time.

A password credential whose `hashIterations` is above one million is **skipped
and named** with the count, because sign-in will not spend that much on one
attempt. Such users sign in through recovery or delegated sign-in. It used to
be imported, and then refused at every attempt.

## PKCE is required of every imported client

Every client created here requires a PKCE challenge, imported ones included.
The importer once required it only of public clients, so every imported
confidential client accepted an authorization request without a challenge.
That is the one change an imported application may notice. A confidential
browser-flow client whose code sends no `code_challenge` is refused at its first
sign-in after cutover. The import report lists every confidential client this
applies to. Check each one before you switch DNS, and opt out any that cannot
send a challenge:

```sh
signari client set-pkce -client-id <id> -require-pkce=false
```

You can also send `PATCH /admin/clients/{id}` with `{"require_pkce": false}`.
A public client cannot opt out.

## Grants, and the bug that was fixed here (21 August 2026)

Keycloak calls the client credentials grant **"service accounts"**
(`serviceAccountsEnabled`), and a client may have it alongside the browser flow
or on its own.

The importer read that field off the realm export and dropped it. Every imported
client was written with `grant_types` hardcoded to `authorization_code` +
`refresh_token`. Two cases came out wrong, in opposite directions:

- **Both flows enabled.** The client was imported and its browser logins worked
  perfectly. Its machine-to-machine calls began failing `unauthorized_client` at
  cutover, with nothing in the migration report mentioning it. This is the
  dangerous half: the migration looks successful, because the part a human tests
  by hand is the part that still works. It is found by whichever batch job runs
  next, which may be a month later.
- **Service accounts only.** Skipped, and reported as *"not using the
  authorization code flow"* — true, and beside the point, because this server
  implements the grant that client does use.

The importer had already stated the right principle, one comment above the bug:
a client *"created here in a shape that cannot work ... is worse than leaving it
out and saying so."* It was applied to the clients left out and not to the ones
brought in.

Grants are now derived from the source client:

| Keycloak client | Imported grants |
|---|---|
| `standardFlowEnabled` | `authorization_code`, `refresh_token` |
| `serviceAccountsEnabled`, confidential | `client_credentials` |
| both | all three |
| `serviceAccountsEnabled` on a **public** client | no `client_credentials` |
| neither flow | skipped, and reported |

**A public client never receives `client_credentials`.** Keycloak does not permit
service accounts on one, and a public client holds no secret to authenticate the
grant with — importing it would create exactly the unusable shape the skip exists
to prevent.

The tests assert the negative cases as hard as the positive ones. An import that
*widens* a client's grants is a privilege escalation performed by the migration
tool, on every client at once, at the moment an operator is least able to audit
it — so `kc-browser`, which had no service account, must not come out with one.

```
CAUGHT   hardcode the grant list again (the state before this pass)
CAUGHT   give client_credentials to public clients too
CAUGHT   give every imported client client_credentials
```

## Names

`firstName` and `lastName` become the account's given name and surname, and
together its display name. They are released under the `profile` scope as
`given_name`, `family_name` and `name`, in the ID token and at userinfo, and
advertised in `claims_supported`. A second import fills only names an account
does not have, so a name changed after the move is never put back. Until
October 2026 the importer read both fields and wrote neither, and no name was
released at all.
