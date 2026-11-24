# Password migration

## Introduction

Moving people onto Signari should not make all of them reset their password. Their
passwords are still in the system you are leaving, and that system can still check
them.

With password migration, the old provider or directory checks the password the
first time each person signs in here. When it is accepted, a hash is kept here, and
the old system is never asked about that person again.

You set up one "migration source" for each organisation, with
`signari migration-source add`, or through the Admin API.

## Who is migrated

Migration applies to people whose account is **pending**. These are imported
accounts, and accounts a [directory sync](cli.md) creates while the organisation
has an enabled source.

Someone with a password here is never sent to the old system, and nobody else is
either. "Delegation", asking the old system to check a password, is only for an
account marked pending, in an organisation with an enabled source.

## Configuring the source

Each organisation has one source, of one of three kinds. Add the source, test it
with an account you know, then enable it:

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

# Anything else: a small service of yours that can check a password against the old
# system. Registered as a provider first, then named as the source.
signari provider add -org <uuid> -hook password_verify \
  -provider-url https://migrate.internal/verify -mode fail_closed
signari migration-source add -org <uuid> -kind hook -name "Old system"

# Test it with an account you know, before anyone depends on it:
signari migration-source test -org <uuid> -username alice     # the password is read from stdin

signari migration-source enable -org <uuid>
signari migration-source show -org <uuid>
```

In this example, the first kind checks the password with a Lightweight Directory
Access Protocol ([LDAP](glossary.md#ldap)) [bind](glossary.md#bind) as the person.
The second asks an old OAuth provider's token endpoint. The third asks a service of
your own, through the `password_verify` hook.

You can do the same with `PUT /admin/organizations/{orgID}/migration-source` in the
[Admin API](admin-api.md), and test with `POST …/migration-source/test`.

**Test before you enable.** The test asks the source exactly as a pending person's
first sign-in will, and names the step that stopped it:

- `configuration`: an insecure URL, or a template with no `{username}`;
- `dial`: the address cannot be reached, or is private and not allowed;
- `tls`: the certificate is not trusted (the certificate authority, or StartTLS);
- `bind`: the directory refused the bind, with its result code, so a wrong
  template's `noSuchObject` reads differently from a wrong password;
- `answer`: the token endpoint refused, as when it does not know Signari's client.

Until October 2026 the first person to sign in after `enable` was the test, and
their sign-in was the one that failed.

A source is created **disabled**. While it is enabled, the password a pending person
types is sent to it. So switching it on is a decision, not a default.

Running `add` again replaces the source. Leaving `-client-secret` out keeps the
stored one only while the token endpoint and client ID stay the same. Changing
either without a secret is refused. The stored secret was issued by the old
provider, and would otherwise be sent to the new endpoint.

## What is enforced, not configured

Some protections are always on, whatever the source:

- **Encrypted transport only.** A token endpoint must be `https://`. A directory
  must be `ldaps://`, or `ldap://` with StartTLS completed. A failed StartTLS is
  refused, never continued in the clear.
- **The username is escaped into the distinguished name (DN).** `{username}` is
  replaced with the identifier the person typed, escaped as RFC 4514 requires. So it
  cannot name a different entry.
- **Internal addresses are reached only when named.** The old system is usually
  internal, so put its address in `SIGNARI_OUTBOUND_ALLOW_PRIVATE`. A stored URL
  cannot reach anything that variable does not list.
- **An empty password is never sent.** RFC 4513 §5.1.2 makes a bind with an empty
  password an unauthenticated bind, which some directories answer with success.
- **An outage is not a wrong password.** Sometimes the old system cannot be
  reached, or its certificate cannot be verified. Then the person is told sign-in
  is temporarily unavailable. The attempt is not counted against them. A wrong password is charged
  like any other. Until October 2026 a directory that could not be reached counted
  as a wrong password.

## Watching the cutover

The "cutover" is the move from the old system to Signari. `migration-source show`
reports how many people are still pending, and how many have migrated through the
source. It also reports how many verifications the source accepted and refused,
with the last error.

> [!WARNING]
> People who never sign in stay pending. Before the old system is switched off,
> they need a password reset or an invitation. Otherwise they will not be able to
> sign in with a password.
