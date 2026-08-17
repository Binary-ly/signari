# Kerberos (SPNEGO)

A user already signed in to a Windows domain or a FreeIPA realm holds a Kerberos
ticket. SPNEGO lets the browser present it, and signing in becomes no
interaction at all — no password, no prompt.

## Configuration

```
SIGNARI_KERBEROS_KEYTAB=/etc/signari/http.keytab
SIGNARI_KERBEROS_REALM=EXAMPLE.COM
SIGNARI_KERBEROS_SPN=HTTP/auth.example.com
```

`/login/kerberos` is registered **only when a keytab loads**. A route answering
`401 WWW-Authenticate: Negotiate` with no keytab behind it makes every
domain-joined browser show a native credential dialog for a service that cannot
check the answer.

The keytab is read at startup, and a bad one refuses to start:

```
signari: SIGNARI_KERBEROS_KEYTAB: /etc/signari/http.keytab is not a keytab:
invalid keytab data. First byte does not equal 5. Export it with `ktpass` on
Windows or `ipa-getkeytab` on FreeIPA -- a krb5.conf or a certificate will
produce exactly this error
Run `signari kerberos check -keytab /etc/signari/http.keytab` to see what is
wrong with it
```

## `signari kerberos check` is worth more than the feature

Kerberos fails in ways the error never explains. A wrong service principal, a
keytab exported at the wrong key version, a clock forty seconds out, an
encryption type the KDC has disabled — every one of them reaches the **user** as
the browser quietly falling back to a password prompt, and reaches the
**operator** as nothing at all.

```sh
signari kerberos check -keytab http.keytab -realm EXAMPLE.COM \
  -spn HTTP/auth.example.com
```

The right realm, the wrong hostname — the commonest mistake there is:

```
    HTTP/old-name.example.com@EXAMPLE.COM   kvno 3   aes256-cts-hmac-sha1-96

  PROBLEM: no entry for HTTP/auth.example.com.
    The browser asks the KDC for a ticket to THIS name. A keytab without it
    authenticates nobody, and the browser falls back to a password prompt
    without saying why.
```

A keytab that stopped working when the KDC was upgraded:

```
  ! HTTP/auth.example.com@EXAMPLE.COM   kvno 1   rc4-hmac (WEAK — disabled by
                                                 default on current KDCs)

  PROBLEM: every entry uses an encryption type current KDCs disable.
    Re-export with AES: ktpass ... /crypto AES256-SHA1, or
    ipa-getkeytab without -e rc4-hmac.
```

It runs with no database, so it can be used on the machine that will serve
SPNEGO before anything else is configured.

## The mapping is where the security is

None of Kerberos is implemented here — `gokrb5` validates the ticket, and
rewriting keytab parsing, encryption types, the replay cache and clock skew
would be a project with a worse outcome. What is ours is deciding which person a
principal is, and every refusal below would be a bypass if it were permissive:

| Principal | |
|---|---|
| `alice@EXAMPLE.COM` | → `alice@example.com` (or `alice` with `SIGNARI_KERBEROS_STRIP_REALM=1`) |
| `alice@PARTNER.EXAMPLE` | **refused.** A ticket from another realm is not a user of this one, even where a trust exists |
| `alice/admin@EXAMPLE.COM` | **refused.** An administrative principal is not the person who shares its first component |
| `HTTP/host@EXAMPLE.COM` | **refused.** A service principal is not a person |
| `alice` | **refused.** No realm, and guessing one is guessing who vouched for them |

## A ticket does not create an account

A valid ticket proves the realm knows this principal. It does not decide the
principal should have an account here, and creating one on the strength of a
ticket makes every principal in the realm a user the moment they visit.

Accounts come from the directory sync — a deliberate act by an administrator. An
unmatched principal is refused and told to ask for one.

## Syncing users from a realm

Use the **LDAP source** against Active Directory or FreeIPA, which is how it
works in practice: both publish the directory over LDAP, and Signari already
handles their flavour-specific immutable identifiers (`objectGUID`,
`ipaUniqueID`). See [ldap-source.md](ldap-source.md).

Reading principals out of a KDC with `kadmin` is a different and worse route to
the same list.

## `amr` is `krb`

Kerberos is single factor. The access policy can require a second one:

```yaml
- name: admin-console-needs-more-than-a-ticket
  when: {client: admin-console}
  require: {phishing_resistant: true}
  message: The console needs a passkey as well as your domain sign-in.
```

## What has not been verified

**No real KDC.** The keytab loading, principal mapping, encryption-type
reporting and the SPNEGO challenge are all tested, and ticket validation is
`gokrb5`'s, which is widely used. But no ticket from a real Active Directory has
been through this. That needs a domain controller, and it is in
`TODO-FOR-YOU.md` rather than implied to be done.
