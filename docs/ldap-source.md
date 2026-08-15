# LDAP as a source: OpenLDAP, Active Directory, FreeIPA

The **inbound** direction. `internal/ldapd` lets applications bind to Signari;
this lets Signari read an organisation's existing directory, so a company with
Active Directory can adopt it without re-entering everybody.

```sh
signari dir add -org <uuid> -kind ldap -slug corp \
  -ldap-url ldaps://dc01.corp.example:636 \
  -ldap-bind-dn "cn=signari,ou=service,dc=corp,dc=example" \
  -ldap-password "$BIND_PW" \
  -ldap-base-dn "ou=people,dc=corp,dc=example" \
  -ldap-flavour ad \
  -ldap-ca /etc/signari/corp-ca.pem

signari dir sync -slug corp            # preview, writes nothing
signari dir sync -slug corp -apply
```


## It reuses the Google/Entra reconciler on purpose

Same plan, same dry run, same 20% deactivation ceiling, same refusal semantics —
described in [directory sync](directory-sync.md). A second table would have meant
a second set of safety rules, and the second set is always the one missing a
check.

## The immutable identifier is the whole design

A DN is not stable. Moving somebody between organisational units rewrites it, and
so does a rename. Email is not stable either. Both are the obvious key, and both
make a rename look like a departure plus an arrival — one account deactivated,
one created, and the person locked out of everything they owned.

| Flavour | Identifier | Login | Name | Disabled |
|---|---|---|---|---|
| `openldap` | `entryUUID` | `uid` | `cn` | — |
| `ad` | `objectGUID` (hex) | `sAMAccountName` | `displayName` | `userAccountControl & 0x2` |
| `freeipa` | `ipaUniqueID` | `uid` | `displayName` | `nsAccountLock` |

An entry without its flavour's identifier is **refused**, never imported under
the DN. Getting this wrong is not a subtle bug; it is a mass lockout on the day
somebody reorganises an OU tree.

Choosing the wrong flavour is a configuration error, not a silent one:

```
every one of the 143 entries found lacks "objectGUID". This is usually the wrong
flavour: Active Directory uses objectGUID, OpenLDAP and FreeIPA use entryUUID or
ipaUniqueID
```

## Verified against a real server

Not a fake. OpenLDAP `slapd` with a private CA, over `ldaps://`:

| | |
|---|---|
| three users, first sync | 3 creates |
| immediate re-sync | **proposes nothing** — no churn |
| rename + move to another OU (`uid`, `cn`, `mail`, DN all change) | **one update**, not a delete plus a create |
| server `sizelimit` smaller than the directory | **error**, not a short list |
| directory emptied upstream | **refused** at 66%, nothing written |

The rename case is the one that matters. `uid=alice,ou=people` became
`uid=alice.anderson,ou=engineering,ou=people` with a new address and a new
display name. Only `entryUUID` was unchanged, and that was enough:

```
update  alice.anderson@example.test: "alice@example.test" -> "alice.anderson@example.test"
```

## The bug a live server found

The anonymous-bind path was written, documented, and covered by a test — and
could not connect to any directory in the world.

Binding anonymously looks like `Bind("", "")`. The client library **refuses that
before it reaches the wire**, because a *real* DN with an empty password is an
"unauthenticated bind" that succeeds on most servers and leaves the connection
anonymous — so an application binding with a service account and a blank password
gets a cheerful success and none of the access it believes it has.

The test's fake connection accepted `Bind("", "")`, which is what a fake does.
Only a real server said no. The fix is the separate `UnauthenticatedBind` call,
and the fake now records the two cases distinctly so the test can tell them
apart. A second guard was added while fixing it: a bind DN with an empty password
is now refused outright, since that is the trap the library was warning about.

## No `InsecureSkipVerify`

There is no flag for it and there will not be one. A directory sync carries every
employee's identity; an unverified server is a machine-in-the-middle feeding you
a directory of its own choosing, and "everybody left" is a plan this engine will
at least refuse — but "here are some new administrators" is not.

Internal directories use internal CAs, so `-ldap-ca` takes the bundle. It is
parsed at `dir add`, not at first sync, so a wrong path is a message now rather
than a cron job failing quietly at 3am.

`ldap://` without StartTLS is refused at configuration:

```
refusing a plaintext bind to "ldap://dc01.corp.example": the bind password can
usually read the whole directory. Use ldaps:// or leave StartTLS on
```

## Paged, because unpaged searches truncate

Searches use RFC 2696 paged results. A plain search stops at the server's size
limit and **reports success** — the silent truncation the whole safety design
exists to prevent. Proven above by shrinking a real server's `sizelimit` below
the directory size: the sync errors instead of reporting that 13 of 15 people
left the company.

The bind matters when testing this. slapd's `rootdn` is exempt from `sizelimit`,
so a first attempt that binds as the admin proves nothing at all.
