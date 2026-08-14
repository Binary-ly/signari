# LDAP

For applications that can only authenticate by binding to a directory.

```sh
SIGNARI_LDAP_ADDR=0.0.0.0:636 \
SIGNARI_LDAP_BASE_DN="dc=example,dc=com" \
SIGNARI_LDAP_ORG_ID=<org-uuid> \
signari serve -addr :443 -tls-cert cert.pem -tls-key key.pem
```

The listener is off unless `SIGNARI_LDAP_ADDR` is set. It is a second
authentication surface, and one nobody asked for should not be listening.

Users bind as `uid=<username>,<base-dn>`.

## What this is, and what it deliberately is not

It is a **compatibility shim**: bind and search, read-only. It is not a
directory. There is no write path, no schema, no replication, no `modify`, no
`add`, no `delete` — those are **refused**, not stubbed, because a
half-implemented directory is one somebody eventually depends on.

Positioned that way on purpose. The alternative — implementing enough of a
directory to be plausible — means owning schema, referential integrity and
replication semantics, none of which this product wants to be responsible for.

## The rule the CVE record points at

**CVE-2017-14623**, against go-ldap:

> "an attacker may be able to login with an empty password. This issue affects an
> application using this package if these conditions are met: (1) it relies only
> on the return error of the Bind function call to determine whether a user is
> authorized... and (2) it is used with an LDAP server allowing unauthenticated
> bind."

RFC 4513 §5.1.2 names that case: a simple bind carrying a DN and an **empty
password** is an *unauthenticated* bind. The person supplied a name; they proved
nothing. Applications ask "did the bind return an error" and read `nil` as
"authenticated", so a server that answers success here hands every one of them a
bypass.

Empty passwords are refused. There is no configuration option to allow it, and
the refusal happens **before** the credential checker is reached, so it is
structural rather than a comparison that happened to fail.

Verified with `ldapwhoami`, not with our own client:

```
$ ldapwhoami -x -H ldaps://... -D "uid=alice,dc=signari,dc=test" -w ""
ldap_bind: Invalid credentials (49)
    additional info: a bind with an empty password authenticates nobody
                     (RFC 4513 section 5.1.2)
```

## Other decisions

**Anonymous search is off by default.** An anonymous search endpoint is a user
directory published to anyone who can reach the port, which is how internal
address books end up in breach dumps. `SIGNARI_LDAP_ANONYMOUS_SEARCH=1` enables
it deliberately.

**No `userPassword` attribute is ever returned**, at any value. Some directories
return a hash; some return a placeholder. Both teach applications to compare
credentials themselves, which is how a password ends up compared with `==` in
somebody else's code.

**`compare` is refused.** It answers "does this attribute equal this value",
which against a password attribute is a guessing oracle with no failed-login
counter anywhere near it.

**StartTLS is refused; LDAPS is supported.** A server that answers success to
StartTLS without actually upgrading the connection has told the client the
channel is protected, and the client then sends a password over it in the clear.
Supplying `-tls-cert` makes the LDAP listener LDAPS; without one it warns loudly
that every bind crosses the network readable.

**A failed re-bind drops the identity.** A connection that stayed bound as its
previous identity would let a client authenticate once and then keep the session
while claiming to be someone else.

**Unknown user and wrong password are indistinguishable**, in both the message
and the timing — the dummy verify runs even when no user was found. Otherwise
the port is a user-enumeration oracle for anyone who can reach it.

**Unsupported filters match nothing.** Failing open on a filter we cannot parse
would answer it with the entire directory.

**One organisation per listener, stated explicitly.** LDAP has no way to express
a tenant — the DN is the only input, and the client chooses it. Inferring the
organisation from attacker-controlled data and getting it wrong means binding
someone against another organisation's directory. `SIGNARI_LDAP_ORG_ID` is
required unless the database holds exactly one organisation.

**Binds go through the same credential path as the sign-in form** — the same
query including its status check, the same Argon2 parameters, the same
throttling. An LDAP front end with its own quiet credential path is a way around
every control the rest of the product has.

## Verified against

`ldapsearch` and `ldapwhoami` from OpenLDAP, and `go-ldap` in the test suite —
separate implementations by different authors. Testing our server with our own
client would only prove we are self-consistent, and self-consistency is what a
protocol bug looks like from the inside.

One bug came from that: a bind DN of `uid=alice` with **no base suffix at all**
was accepted, because the suffix check only ran when there was something after
the leading RDN. Validation that can be bypassed by omitting the thing being
validated is not validation.

## Not implemented

Referrals, aliases, paged results, substring and approximate filters, SASL, and
every write operation. Substring filters in particular are absent on purpose:
they ask the server to do open-ended work on behalf of whoever opened the
connection.
