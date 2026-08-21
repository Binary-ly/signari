# Migrating from Keycloak

```sh
# On the Keycloak host:
kc.sh export --realm your-realm --file realm.json

# Here — preview first, it writes nothing:
signari import keycloak -file realm.json -org <uuid> -dry-run
signari import keycloak -file realm.json -org <uuid>
```

## What comes across

Users, their existing password hashes, clients with the secrets they already
hold, and redirect URIs. The point of importing a secret rather than issuing a
new one is that the application does not have to be touched: migration becomes a
DNS change instead of a change to every downstream app.

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

## What is deliberately not imported

Names. `core.users` has no name column, so `firstName` and `lastName` are read
past. This is consistent with `claims_supported`, which deliberately omits
`"name"` on the same grounds — advertising a claim nothing can emit is the
failure the metadata builder exists to prevent — but it does mean a Keycloak
realm's display names do not survive the move.
