# LDAP as a source: OpenLDAP, Active Directory, FreeIPA

## Introduction

Acme keeps its people in Active Directory, and does not want to enter them all
again in Signari. Signari can read that directory instead, and keep its own list
of people in step with it.

This is the **inbound** direction. `internal/ldapd` lets applications bind to
Signari over the Lightweight Directory Access Protocol
([LDAP](glossary.md#ldap)). A source works the other way round: it lets Signari
read an organisation's existing directory. So a company with Active Directory can
adopt Signari without re-entering everybody.

You add an LDAP source with `signari dir add -kind ldap`. It uses the same sync,
dry run and safety limits as every [directory sync](directory-sync.md).

> [!NOTE]
> To let applications check passwords against Signari over LDAP, see
> [LDAP](ldap.md).

## Add a source and test it

These commands add an Active Directory source, check that Signari can read it,
and then preview a sync and apply it:

```sh
signari dir add -org <uuid> -kind ldap -slug corp \
  -ldap-url ldaps://dc01.corp.example:636 \
  -ldap-bind-dn "cn=signari,ou=service,dc=corp,dc=example" \
  -ldap-password "$BIND_PW" \
  -ldap-base-dn "ou=people,dc=corp,dc=example" \
  -ldap-flavour ad \
  -ldap-ca /etc/signari/corp-ca.pem

signari dir test -slug corp            # connect, bind, read a few people
signari dir sync -slug corp            # preview, writes nothing
signari dir sync -slug corp -apply
```

In this example, `-ldap-bind-dn` is the account Signari binds as when it reads,
and `-ldap-base-dn` is where it searches. A "bind" is LDAP's request that checks
a name and a password. A "DN", or distinguished name, is an entry's full name in
the directory. `-ldap-flavour ad` says the directory is Active Directory, and
`-ldap-ca` holds the certificate authority (CA) roots that verify the directory
server.

Through the Admin API, an LDAP source is registered only by a deployment-wide
token. The engine dials its URL from inside the deployment's network. So
choosing the URL is choosing where the engine connects, and that is not a
setting for one organisation's administrator. See [the Admin API](admin-api.md).

## Several servers, and asking one before trusting it

`-ldap-url` can name replicas, separated by spaces, tried in order:

```sh
signari dir add -org <uuid> -kind ldap -slug corp \
  -ldap-url "ldaps://dc01.corp.example:636 ldaps://dc02.corp.example:636" \
  ...
```

The next server is tried only when one cannot be reached, or its Transport Layer
Security ([TLS](glossary.md#tls)) fails. TLS is the encryption behind
`ldaps://`.

A server that answers and refuses the bind is not passed over. The password is
wrong for all of them, and trying each one in turn would lock the service
account on every replica. Each URL is held to the
[rule below](#no-insecureskipverify) on its own. So one plaintext entry in a list
is refused, however good the others are.

`signari dir test` (`POST .../directories/{slug}/test`) reads the directory as a
sync would, and changes nothing, in the directory or in Signari. It works on a
disabled source, so a source can be checked before it is turned on. It says
where it stopped:

| Step | Means |
|---|---|
| `connect` | No server could be reached, or TLS failed |
| `bind` | The server answered and refused the credentials |
| `search` | The bind worked and the search failed or found nobody, so the base DN or the filter is wrong |
| `identity` | An entry has no value for what this flavour tracks people by, so the flavour is wrong for this server |

It reads five entries. A server that stops there on a size limit has still
answered, so that counts as success. `dir sync` is what proves the whole
directory reads, and its paged search treats a short list as a failure.

## Reading more than a flavour names

A flavour says where a person's identifier, address and name are kept. An
attribute map says what else to read, and where those three are kept when the
convention is wrong for this directory:

```sh
signari dir set -slug corp \
  -attribute-map "employeeNumber=employee_number,department=department,userPrincipalName=email"
signari dir sync -slug corp            # shows how many values would change
```

The left of each pair is an LDAP attribute, matched in any case. The right is a
declared attribute, or `email` or `name`, which replace what the flavour reads
for those two.

An attribute has to be [declared](admin-api.md#attributes-of-people) first, through
the Admin API or a configuration file. Its declaration decides its type, and
whether it is sealed. `-attribute-map ""` clears the map, and
`PATCH .../directories/{slug}` takes the same thing as `attribute_map`. Only an
LDAP source has one: Google and Entra report what their APIs do.

A mapped attribute belongs to the directory. Each sync writes what the directory
says, so a value changed in Signari goes back at the next sync. A value the
directory no longer holds is cleared in Signari. There are limits on that:

- If no entry at all carries an attribute, nobody's is cleared and the report
  says so. A bind account that cannot read an attribute looks exactly like a
  company with no departments. This is the same rule a short list gets.
- A required attribute is never cleared.
- A value the attribute's type refuses, or one that is not text, is reported by
  person and attribute and left out. The rest of the sync goes on.
- A person who may act as others keeps their values, and the trail records
  `directory.privileged_skipped`. These values can feed claims, and
  administering the directory does not make anybody an administrator in Signari.
- A person with several values gets the first the directory server returns.

Values are never printed. The report and the audit record give counts and names.

## It reuses the Google/Entra reconciler on purpose

An LDAP source has the same plan, the same dry run, the same 20% deactivation
ceiling and the same refusals as Google and Entra. They are described in
[directory sync](directory-sync.md). A second table would have meant a second
set of safety rules, and the second set is always the one missing a check.

## The immutable identifier is the whole design

A DN is not stable. Moving somebody between organisational units (OUs) rewrites
it, and so does a rename. Email is not stable either. Both are the obvious key.
Both make a rename look like a departure plus an arrival: one account
deactivated, one created, and the person locked out of everything they owned.

So each flavour tracks people by an identifier that does not change:

| Flavour | Identifier | Login | Name | Disabled |
|---|---|---|---|---|
| `openldap` | `entryUUID` | `uid` | `cn` | — |
| `ad` | `objectGUID` (hex) | `sAMAccountName` | `displayName` | `userAccountControl & 0x2` |
| `freeipa` | `ipaUniqueID` | `uid` | `displayName` | `nsAccountLock` |

An entry without its flavour's identifier is **refused**, never imported under
the DN. Getting this wrong is not a subtle bug. It is a mass lockout on the day
somebody reorganises an OU tree.

Choosing the wrong flavour is a configuration error, not a silent one:

```
every one of the 143 entries found lacks "objectGUID". This is usually the wrong
flavour: Active Directory uses objectGUID, OpenLDAP and FreeIPA use entryUUID or
ipaUniqueID
```

## Verified against a real server

This was checked against a real server, not a fake: OpenLDAP's `slapd` with a
private CA, over `ldaps://`.

| | |
|---|---|
| three users, first sync | 3 creates |
| immediate re-sync | **proposes nothing** — no churn |
| rename + move to another OU (`uid`, `cn`, `mail`, DN all change) | **one update**, not a delete plus a create |
| server `sizelimit` smaller than the directory | **error**, not a short list |
| directory emptied upstream | **refused** at 66%, nothing written |

The rename case is the one that matters. `uid=alice,ou=people` became
`uid=alice.anderson,ou=engineering,ou=people`, with a new address and a new
display name. Only `entryUUID` was unchanged, and that was enough:

```
update  alice.anderson@example.test: "alice@example.test" -> "alice.anderson@example.test"
```

## The bug a live server found

The anonymous-bind path was written, documented and covered by a test. It could
not connect to any directory in the world.

Binding anonymously looks like `Bind("", "")`. The client library **refuses that
before it reaches the wire**. A *real* DN with an empty password is an
"unauthenticated bind", which succeeds on most servers and leaves the connection
anonymous. So an application binding with a service account and a blank
password gets a cheerful success, and none of the access it believes it has.

The test's fake connection accepted `Bind("", "")`, which is what a fake does.
Only a real server said no. The fix is the separate `UnauthenticatedBind` call.
The fake now records the two cases distinctly, so the test can tell them apart.

A second guard was added while fixing it. A bind DN with an empty password is
now refused outright, since that is the trap the library was warning about.

## No `InsecureSkipVerify`

`InsecureSkipVerify` turns off the check of a server's certificate. There is
no flag for it, and there will not be one. A directory sync carries every
employee's identity. An unverified server is a machine-in-the-middle feeding you
a directory of its own choosing. "Everybody left" is a plan Signari will at
least refuse, but "here are some new administrators" is not.

Internal directories use internal CAs, so `-ldap-ca` takes the bundle. It is
parsed at `dir add`, not at first sync. So a wrong path is a message now, rather
than a cron job failing quietly at 3am.

`ldap://` without StartTLS is refused at configuration:

```
refusing a plaintext bind to "ldap://dc01.corp.example": the bind password can
usually read the whole directory. Use ldaps:// or leave StartTLS on
```

## Paged, because unpaged searches truncate

Searches use RFC 2696 paged results. A plain search stops at the directory
server's size limit and **reports success**. That is the silent truncation the whole safety
design exists to prevent.

It was proven above by shrinking a real server's `sizelimit` below the directory
size. The sync errors, instead of reporting that 13 of 15 people left the
company.

The bind matters when testing this. `slapd`'s `rootdn` is exempt from
`sizelimit`. So a first attempt that binds as that administrator account proves
nothing at all.
