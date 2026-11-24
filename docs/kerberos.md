# Kerberos (SPNEGO)

## Introduction

Many companies already sign their people in to their computers with
[Kerberos](glossary.md#kerberos), through a Windows domain or a FreeIPA realm. A
person signed in that way already holds a Kerberos "ticket": proof, from the
domain, of who they are.

Signari can accept that ticket. Through the Simple and Protected GSS-API
Negotiation Mechanism ([SPNEGO](glossary.md#spnego)), the browser presents it, and
signing in becomes no interaction at all: no password, no prompt. [Which protocol
do I need?](protocols-explained.md#kerberos) explains Kerberos in plain words.

You give Signari a "keytab", the file that holds the service's Kerberos keys. You
can set one for the whole deployment with environment variables, or one for each
organisation with the command line or the Admin API.

## Configuration

A Kerberos "realm" is the domain that issues the tickets, such as `EXAMPLE.COM`.
A "principal" is a name the Kerberos realm knows, for a person or a service. The
"service principal name" (SPN) is the name a browser asks for a ticket to. To
accept tickets for the whole deployment, set the keytab, the Kerberos realm and
the SPN:

```
SIGNARI_KERBEROS_KEYTAB=/etc/signari/http.keytab
SIGNARI_KERBEROS_REALM=EXAMPLE.COM
SIGNARI_KERBEROS_SPN=HTTP/auth.example.com
```

A browser signs in with its ticket at `/login/kerberos`. Its `authz=` parameter
carries the authorization request it should come back to. The sign-in page links
there, as "Sign in with your domain account", when both of these are true:

- the host it was asked on has a keytab for the page's organisation;
- the organisation's [sign-in flow](flows.md) admits a ticket.

An organisation whose flow admits a ticket and nothing else is sent there straight
from the authorization request, with no page at all. Until November 2026, nothing
linked it. So a ticket signed somebody in only through a link the administrator
gave people themselves.

`/login/kerberos` answers **only for a host with a keytab behind it**, and is a
`404` otherwise. Picture a route answering `401 WWW-Authenticate: Negotiate` with
no keytab behind it. It makes every domain-joined browser show a native credential
dialog, for a service that cannot check the answer.

The keytab is read at startup. With a bad one, Signari refuses to start, and says
why:

```
signari: SIGNARI_KERBEROS_KEYTAB: /etc/signari/http.keytab is not a keytab:
invalid keytab data. First byte does not equal 5. Export it with `ktpass` on
Windows or `ipa-getkeytab` on FreeIPA -- a krb5.conf or a certificate will
produce exactly this error
Run `signari kerberos check -keytab /etc/signari/http.keytab` to see what is
wrong with it
```

A Kerberos realm named this way is the deployment's, and signs people in to its
first organisation. That suits a deployment with one organisation.

## A Kerberos realm for each organisation

Several organisations may each have a domain of their own. Each then registers its
own Kerberos realm:

```sh
signari kerberos add-realm -org <uuid> -realm CORP.EXAMPLE.COM \
  -host sso.corp.example.com -spn HTTP/sso.corp.example.com \
  -keytab /tmp/corp.keytab
```

A browser gets a ticket for the host it is talking to. So the host says which
Kerberos realm's key opens the ticket, and whose organisation the person is in.
The name is the one the browser sends, without a port, and one host answers for
one Kerberos realm.

The keytab is the key to every ticket of that service. So it is sealed under the
root key, rotated with it, and never comes back out. You can delete the file once
this has run.

A keytab holding no key for the service principal in the Kerberos realm is
refused. It
would open no ticket, and look like a working one until somebody tried. It is read
on each request, so `signari kerberos remove-realm` stops both ways in on commit.

A host with no Kerberos realm of its own falls back to the environment's, and a
host with neither is a `404`.

`-strip-realm` matches `alice@EXAMPLE.COM` by the name `alice`, against a person's
username or address, for a Kerberos realm whose names are not addresses.

## `signari kerberos check` is worth more than the feature

Kerberos fails in ways the error never explains. The domain's ticket server is the
Key Distribution Center (KDC). Any of these can be the cause:

- a wrong service principal;
- a keytab exported at the wrong key version;
- a clock forty seconds out;
- an encryption type the KDC has disabled.

Every one of them reaches the **person** as the browser quietly falling
back to a password prompt. It reaches the **administrator** as nothing at all.

`signari kerberos check` reads a keytab, and says what is wrong with it:

```sh
signari kerberos check -keytab http.keytab -realm EXAMPLE.COM \
  -spn HTTP/auth.example.com
```

This output shows the right Kerberos realm with the wrong hostname, the commonest mistake
there is:

```
    HTTP/old-name.example.com@EXAMPLE.COM   kvno 3   aes256-cts-hmac-sha1-96

  PROBLEM: no entry for HTTP/auth.example.com.
    The browser asks the KDC for a ticket to THIS name. A keytab without it
    authenticates nobody, and the browser falls back to a password prompt
    without saying why.
```

This one shows a keytab that stopped working when the KDC was upgraded:

```
  ! HTTP/auth.example.com@EXAMPLE.COM   kvno 1   rc4-hmac (WEAK — disabled by
                                                 default on current KDCs)

  PROBLEM: every entry uses an encryption type current KDCs disable.
    Re-export with AES: ktpass ... /crypto AES256-SHA1, or
    ipa-getkeytab without -e rc4-hmac.
```

It runs with no database. So you can use it on the machine that will serve SPNEGO,
before anything else is configured.

## The mapping is where the security is

None of Kerberos is implemented here. `gokrb5` validates the ticket. Rewriting
keytab parsing, encryption types, the replay cache and clock skew would be a
project with a worse outcome.

What Signari does itself is decide which person a principal is. Every refusal
below would be a bypass if it were permissive:

| Principal | |
|---|---|
| `alice@EXAMPLE.COM` | → `alice@example.com` (or `alice` with `SIGNARI_KERBEROS_STRIP_REALM=1`) |
| `alice@PARTNER.EXAMPLE`, with `-trust-realms PARTNER.EXAMPLE` | → `alice@partner.example`, and never `alice`: stripping both would hand this Kerberos realm's alice to the other |
| `alice@PARTNER.EXAMPLE` | **refused.** A ticket from another Kerberos realm does not name a person of this one, even where a trust exists |
| `alice/admin@EXAMPLE.COM` | **refused.** An administrative principal is not the person who shares its first component |
| `HTTP/host@EXAMPLE.COM` | **refused.** A service principal is not a person |
| `alice` | **refused.** No Kerberos realm, and guessing one is guessing who vouched for them |

## A ticket does not create an account

A valid ticket proves the Kerberos realm knows this principal. It does not decide
that the principal should have an account here. Creating one on the strength of a
ticket would give every principal in the Kerberos realm an account the moment they
visit.

Accounts come from the directory sync, a deliberate act by an administrator. An
unmatched principal is refused, and told to ask for one.

A Kerberos realm can decide otherwise, by name. This command registers one that
admits a partner Kerberos realm's people, and creates accounts for them:

```sh
signari kerberos add-realm -org "$ORG" -realm CORP.EXAMPLE.COM -host sso.corp.example.com \
  -spn HTTP/sso.corp.example.com -keytab service.keytab \
  -trust-realms PARTNER.EXAMPLE -create-accounts
```

`-trust-realms` admits the people of another Kerberos realm. A trust between KDCs
says a ticket is genuine, not that its holder is welcome, so nothing but this list
admits one. It checks who the ticket says the person is. It leaves which Kerberos
realms the ticket came through to your KDCs.

`-create-accounts` makes an account for a good ticket that has none. The account is
active, with no password. That is the choice this section argues against, and yours
to make. Every principal known to the Kerberos realm, or to the Kerberos realms it
trusts, can now arrive.

The [`user_create` hook](extensibility.md) is asked first, with
`source: kerberos`. A name held by an account that is deactivated, locked or
waiting for approval is refused, not taken over. Each account it makes is recorded
as `kerberos.user_created`.

The two can be set on a Kerberos realm from `signari kerberos add-realm` and the
Admin API. A Kerberos realm registered before they existed has neither.

Forwarding a ticket to the engine (GSS delegation) is not offered. A forwarded
credential is a person's ticket-granting ticket, and nothing here would use one.

## The three ways a Kerberos realm is used

Signari can use a Kerberos realm in three ways:

| | |
|---|---|
| **SPNEGO** | A domain-joined browser signs in with no interaction |
| **Password backend** | A password typed at the sign-in form is verified against the KDC, at every sign-in |
| **Directory sync** | Accounts are created from the Kerberos realm's principals |

### Password backend

This is for somebody on a machine that is not domain-joined, typing the password
they already have. The Kerberos realm is a source that a password is delegated to, as a
directory being migrated from is. To add it, test it with one person, and turn it
on:

```sh
signari migration-source add -org <uuid> -kind kerberos -name "Corp" -realm EXAMPLE.COM
signari migration-source test -org <uuid> -username alice
signari migration-source enable -org <uuid>
```

It applies to a person with no password here who is marked pending, which is what
`signari kerberos sync` makes. It differs from a migration in one way: **no hash is
kept.** The Kerberos realm stays the authority, and a person is asked about at
every sign-in. A hash kept here would go on working after the Kerberos realm had
changed the password or disabled the account.

Wrong passwords are charged as any others are, to the address and the captcha. A
KDC that does not answer is an outage, charged to nobody.

There is no hash to compare. A Kerberos realm does not publish password material, and the
only way to check a password is to ask the KDC for a ticket with it. That also
makes every check live. A password changed, or an account disabled, five seconds
ago is refused, which a cached hash cannot do.

**A ticket from the KDC is not enough on its own**. Whoever answers an
Authentication Service (AS) request chooses the key its reply is encrypted with.
So a KDC that an attacker stands up on the network says yes to any password.

The verifier therefore goes on to ask for a ticket to this service, and opens it
with the service's key. That is the organisation's own key when
`kerberos add-realm` gave it that Kerberos realm. Otherwise it is
`SIGNARI_KERBEROS_SPN` and `SIGNARI_KERBEROS_KEYTAB`. Only the Kerberos realm's KDC
holds that key.

A krb5 configuration naming every Kerberos realm's KDCs is still one file,
`SIGNARI_KERBEROS_CONF`. The Kerberos realm is asked about a person by their
username when they have one, whatever they typed. That is because the Kerberos
realm has a principal for them, not an address.

The keytab and the principal are required. A ticket that will not open, or names
somebody else, is refused. That is reported as the source failing, not as a wrong
password. A person typing their password into a form is not who to blame for a KDC
on the wrong end of the wire.

Four things are refused **before** the KDC is asked, and each would be a bypass
otherwise:

- An **empty password**. Some KDC configurations accept it as a pre-auth-less
  bind, producing an authenticated session for a password nobody typed.
- An **administrative principal** (`alice/admin`).
- A principal naming **another Kerberos realm**.
- And a KDC that does not answer is reported as unreachable, never as a wrong
  password. The alternative sends an office to reset passwords they typed
  correctly.

The password backend needs `/etc/krb5.conf`, or the file `SIGNARI_KERBEROS_CONF`
names, to name the KDCs. It is read fresh on each verification. So a Kerberos
realm whose KDCs move is fixed by editing a file, not by a restart.

### Directory sync

To list a Kerberos realm's principals, then create accounts from them:

```sh
signari kerberos principals -realm EXAMPLE.COM \
  -admin-principal signari/admin@EXAMPLE.COM -keytab admin.keytab

signari kerberos sync -org <uuid> -realm EXAMPLE.COM \
  -admin-principal signari/admin@EXAMPLE.COM -keytab admin.keytab -apply
```

Service and administrative principals are filtered out, such as `host/web01`,
`HTTP/auth`, `alice/admin`, `krbtgt` and `kadmin`. An account created from one is
an account nobody can explain.

Accounts are created **without a local password**, and marked pending. They sign
in with a ticket (SPNEGO), or with the Kerberos realm's password through the `kerberos`
migration source above. Inventing a local password would be a second way in that
nobody chose.

Nothing is ever deleted. What happens to a leaver is a policy decision, not
something a listing should make. It is a dry run unless `-apply` is given.

A person already here is counted and left as they are, unless `-adopt-existing` is
given. With it, somebody with no password here and no finished migration is marked
pending as well. The Kerberos realm's password then signs them in too, as a ticket
by SPNEGO already does for the same principal name. This is for people a directory
sync brought in from the Kerberos realm's own directory.

Somebody with a local password is never adopted, since they are checked here and
never sent to the Kerberos realm. Neither is anybody whose migration is complete.

**This runs `kadmin`.** The Kerberos administration protocol is a remote
procedure call (RPC) protocol over GSSAPI, with no Go implementation. Writing one
to list principals would be a large amount of protocol code with one consumer.
`kadmin` is on every machine that administers a Kerberos realm, and is the command
an administrator already uses. Its absence is reported plainly, instead of
producing an empty list that looks like an empty Kerberos realm.

**The Lightweight Directory Access Protocol (LDAP) is usually the better route.**
Active Directory and FreeIPA both publish the same principals over LDAP. They give
far richer attributes, and an immutable identifier this engine already
understands. See [LDAP as a source](ldap-source.md). The kadmin path exists for a
Kerberos realm that has neither: MIT Kerberos on its own.

## `amr` is `krb`

A ticket sign-in's `amr`, the claim that lists how the person signed in, is `krb`.
Kerberos is single factor. The access policy can require a second one. This rule
asks for a phishing-resistant factor, such as a passkey, for the `admin-console`
application:

```yaml
- name: admin-console-needs-more-than-a-ticket
  when: {client: admin-console}
  require: {phishing_resistant: true}
  message: The console needs a passkey as well as your domain sign-in.
```

## What has not been verified

**No real KDC.** The keytab loading, principal mapping, encryption-type reporting
and the SPNEGO challenge are all tested. Ticket validation is `gokrb5`'s, which is
widely used. But no ticket from a real Active Directory has been through this.
That needs a domain controller, and it is in the open-decisions list, not implied
to be done.
