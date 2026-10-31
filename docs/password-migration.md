# Password migration

Moving people onto this server without making them all reset their password.
Their old provider or directory checks the password the first time each person
signs in here; when it is accepted, a hash is kept here and the old system is
never asked about that person again.

## Who is migrated

People whose account is **pending**: imported accounts, and accounts a
[directory sync](cli.md) creates while the organisation has an enabled source.
Someone with a password here is never sent to the old system, and nobody else
is either: delegation is only for an account marked pending, in an organisation
with an enabled source.

## Configuring the source

One per organisation, of one of two kinds.

```sh
# The directory itself: a bind as the person.
signari migration-source add -org <uuid> -kind ldap -name "Old directory" \
  -ldap-url ldaps://dir.example.com \
  -bind-dn-template 'uid={username},ou=people,dc=example,dc=com' \
  -ldap-ca ./dir-ca.pem

# An OAuth provider's password grant.
signari migration-source add -org <uuid> -kind oidc_password -name "Old IdP" \
  -token-endpoint https://old.example.com/oauth2/token \
  -client-id-ext migration -client-secret <secret>

# Test it with an account you know, before anyone depends on it:
signari migration-source test -org <uuid> -username alice     # the password is read from stdin

signari migration-source enable -org <uuid>
signari migration-source show -org <uuid>
```

The same is `PUT /admin/organizations/{orgID}/migration-source` in the
[Admin API](admin-api.md), and `POST …/migration-source/test` for the test.

**Test before you enable.** The test asks the source exactly as a pending
person's first sign-in will, and names the step that stopped it:
`configuration` (an insecure URL, a template with no `{username}`), `dial`
(the address cannot be reached, or is private and not allowed), `tls` (the
certificate is not trusted: the CA, or StartTLS), `bind` (the directory refused
the bind, with its result code, so a wrong template's `noSuchObject` reads
differently from a wrong password) or `answer` (the token endpoint refused, as
when it does not know our client). Until October 2026 the first person to sign
in after `enable` was the test, and their sign-in was the one that failed.

A source is created **disabled**. While it is enabled, the password a pending
person types is sent to it, so switching it on is a decision rather than a
default.

Running `add` again replaces the source. Leaving `-client-secret` out keeps the
stored one only while the token endpoint and client id stay the same; changing
either without a secret is refused, because the stored secret was issued by the
old provider and would otherwise be sent to the new endpoint.

## What is enforced, not configured

- **Encrypted transport only.** A token endpoint must be `https://`; a
  directory `ldaps://`, or `ldap://` with StartTLS completed. A failed StartTLS
  is refused, never continued in the clear.
- **The username is escaped into the DN.** `{username}` is replaced with the
  identifier the person typed, escaped as RFC 4514 requires, so it cannot name
  a different entry.
- **Internal addresses are reached only when named.** The old system is
  usually internal; put its address in `SIGNARI_OUTBOUND_ALLOW_PRIVATE`. A
  stored URL cannot reach anything that variable does not list.
- **An empty password is never sent.** RFC 4513 §5.1.2 makes a bind with an
  empty password an unauthenticated bind, which some directories answer with
  success.
- **An outage is not a wrong password.** When the old system cannot be reached,
  or its certificate cannot be verified, the person is told sign-in is
  temporarily unavailable, and the attempt is not counted against them. A wrong
  password is charged like any other. Until October 2026 a directory that could
  not be reached counted as a wrong password.

## Watching the cutover

`migration-source show` reports how many people are still pending, how many
have migrated through the source, and how many verifications it accepted and
refused, with the last error. People who never sign in stay pending: before
the old system is switched off, they need a password reset or an invitation,
or they will not be able to sign in with a password.
