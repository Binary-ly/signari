# Migrating from Zitadel

```sh
# Export one organisation through Zitadel's Admin API, with an IAM token:
curl -X POST https://zitadel.example.com/admin/v1/export \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"org_ids": ["<org id>"], "with_passwords": true, "with_otp": true}' > zitadel.json

# Here — preview first, it writes nothing:
signari import zitadel -file zitadel.json -org <uuid> -dry-run
signari import zitadel -file zitadel.json -org <uuid>
```

One Zitadel organisation goes into one organisation here. An export holding
several is refused rather than merged. Export each one by naming it in
`org_ids`, and import each into its own organisation. Both spellings of the
export's field names are read, `humanUsers` and `human_users`.

A dry run is the import itself, run in a transaction that is rolled back, so its
report is what the import would do.

## What comes across

| In Zitadel | Here |
|---|---|
| Human users | People, with their username, address and whether it was verified, first name, last name and display name. Active users and those still in their initial state come across. Inactive, locked, suspended and deleted ones are skipped and named |
| Password hashes | Kept, and verified as they are at the first sign-in, then replaced with Argon2id. A format that cannot be verified here is counted in the census, and the person is skipped and named |
| TOTP | The same secret, SHA-1, six digits every thirty seconds, as Zitadel enrols one. Needs `SIGNARI_ROOT_KEY` |
| Project roles | Groups named after the project and the role, such as `Billing App` / `admin` → `Billing-App.admin`, with the grants of each role as members |
| IdP links | Kept, where a provider is registered here under the slug that the IdP's name makes: lower case, with other characters as hyphens (`Corporate SSO` → `corporate-sso`) |
| Metadata | Written where the organisation declares an attribute of that name, when the value is text |

Run the import again after registering a provider or declaring an attribute. It
duplicates nothing, and the report names whatever is still missing.

## What does not, and why

- **OIDC and API applications.** Zitadel writes an application into its export
  without its client ID or secret, so it cannot be recreated with the ID the
  application already uses. Each one is named in the report with its redirect
  URIs and post-logout URIs. Register it with
  `signari client create -client-id <the ID it uses>`.
- **The subject.** Zitadel sends each person's user ID as `sub`. That ID is a
  number written as text, and an account's id here, which is what it sends, is
  a UUID. An application that keyed its accounts on `sub` meets every person as
  a stranger. The report says how many people this applies to.
- **Machine users.** They sign in with a key or a secret, and neither is
  exported. Register whatever uses one as a client.
- **Administrative roles**, such as `ORG_OWNER` and project roles held as a
  member. Nothing is granted here by having held them. Each person's roles are
  named, so you can grant what is needed explicitly.
- **Passkeys and recovery codes.** The export does not hold them. People
  register passkeys again, and make new recovery codes.
- Nicknames and phone numbers, and the organisation's policies, texts, actions,
  domains and IdP configurations. Each is counted in the report by field.
