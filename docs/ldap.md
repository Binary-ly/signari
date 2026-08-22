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

It is a **compatibility shim**: bind and search, so that software written against
a directory can authenticate people who live in Signari.

Since August 2026 it can also be **written to** — `add`, `modify`, `delete` and
`modify DN` (RFC 4511 §4.6–§4.9) — against an explicit schema. That is **off by
default** and takes two decisions to turn on. See [Writes](#writes) below.

It is still not a directory. There is no replication, no subschema subentry, no
DIT structure rules, no aliases, no subordinate entries: the tree is flat and
holds `person` entries. Everything outside that is **refused**, not stubbed,
because a half-implemented directory is one somebody eventually depends on.

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

## Writes

    SIGNARI_LDAP_WRITE_GROUP=directory-admins

**Two decisions, not one.** The variable above names *who*; the engine only
builds a writer at all when it is set. A read-only deployment behaves exactly as
it did before writes existed, down to the result code.

**Empty means nobody.** That is the fail-closed reading, and it is right here for
the same reason the SSF stream `Allows` field takes it: reading an unset list as
"everybody" is how a half-made configuration becomes a live grant — and this
particular grant is the ability to rewrite the directory and then bind as anybody
in it.

A **group** rather than a list of DNs, so the people who hold it appear in their
own `memberOf` and are managed with `signari group member` like every other
privilege. Startup logs a warning naming the group, because otherwise the only
evidence is an environment variable nobody may have set deliberately.

A refusal distinguishes the two cases: `unwillingToPerform(53)` for a read-only
directory, `insufficientAccessRights(50)` for a bound identity outside the group.
Those send an administrator to completely different places, and neither tells an
attacker anything they could not learn by trying with any account.

### The schema

`internal/ldapd/schema.go` is an explicit table. Anything not in it is
`undefinedAttributeType(17)` rather than quietly accepted and dropped.

| attribute | | |
|---|---|---|
| `uid` | naming attribute | not modifiable — `notAllowedOnRDN(67)`, which names the operation to use instead |
| `cn` | **MUST** (RFC 4519 `person`) | writable |
| `sn` | **MUST** (RFC 4519 `person`) | writable |
| `givenName`, `displayName`, `mail` | | writable |
| `userPassword` | write-only | never returned by a search, at any value |
| `memberOf` | derived | NO-USER-MODIFICATION — it is a view of group membership |
| `objectClass` | structural | fixed — `objectClassModsProhibited(69)` |

**Three columns had to be added to make this honest.** `cn` had nowhere to go at
all — the shim published `cn: <username>` and this product had never stored a
display name — so an `add` carrying `cn: Alice Okonkwo` would have been accepted
and dropped. And `sn` is a MUST attribute of a class **every entry here has
always declared**, which means every entry this directory ever published was
schema-invalid. Nobody noticed, because almost nothing validates a search result
against a schema it did not fetch. It surfaced from the other direction: working
out what an `add` would have to require.

Rows that predate the column have no surname, so the read side derives one from
the display name. That is a guess and is labelled as one in the code — the
alternative is publishing a `person` with no `sn`, which a schema-aware client is
entitled to reject.

### Result codes

As specific as the specification allows, because a directory client acts on them:
`entryAlreadyExists(68)` tells a provisioning run to move on, `constraintViolation(19)`
tells it to fix the data, `notAllowedOnRDN(67)` tells it to use `modify DN`.
Collapsing everything to `unwillingToPerform` — what a shim reaching for one code
does — turns each of those into "something went wrong, retry forever".

### Modify is atomic, and resolved before it is applied

§4.6: *"The entire list of modifications MUST be performed in the order they are
listed as a single atomic operation ... the client may expect that no
modifications of the DIT have been performed if the Modify Response received
indicates any sort of error."*

So the changes are folded into a **final state** against the entry as it stands,
and the store applies that state in one transaction. Applying them one at a time
against the database would make a failure halfway through a partial write, which
is the one outcome §4.6 promises cannot happen.

The MUST attributes are checked on the **result**, not per change — a request that
deletes `sn` and adds it back is legal; one that only deletes it is not.

### `delete` deletes

It does not deactivate. A directory `delete` that quietly deactivates is the
failure this whole design is against: the client asked for the entry to be gone,
a subsequent search would not find it, and the row would still be there.

It is **not** `signari erase subject`. Deleting removes the row and everything
cascading from it; it does not destroy the subject's data-encryption key, so
ciphertext already written to backups stays readable. Crypto-shredding is a
separate, deliberate act — see [erasure.md](erasure.md).

### `modify DN` and `deleteoldrdn`

§4.9 says that with `deleteoldrdn` FALSE, "the attribute values forming the old
RDN will be retained as non-distinguished attribute values of the entry".

`uid` is single-valued here, so that cannot be represented — and it is **refused**
(`constraintViolation`) rather than ignored. A server that accepted FALSE and
dropped the old value anyway would have done the one thing the flag exists to
prevent.

`newSuperior` is refused for anything but the base DN: this directory is flat, so
the only superior that exists is the naming context, and §4.9 specifies
`noSuchObject` with `matchedDN` for exactly that case.

### Every write is audited, inside its own transaction

A directory write absent from the trail is one nobody can answer for, and
committing the change while the record of it failed would be exactly that.
Deletion is audited **before** the row goes, because afterwards there is no
subject for the event to name.

A password set through this path gets **its own event**, separate from "the entry
was modified". Somebody with directory write access can set any password and then
bind as that person — the most consequential thing this interface can do, and the
thing an investigation looks for.

Passwords go through the **same policy** as the sign-in form. A directory write is
the one path where a password arrives with no person in front of a form to be
told what is wrong with it, which makes it the most likely way to seed an estate
with weak credentials.

### Writes are in-process only

The LDAP **outpost** has no write path back to the engine and refuses everything
with `unwillingToPerform`, as before. Adding one would mean putting directory
mutation on the outpost API, which is deliberately a
password-verification oracle and nothing more.

## Not implemented

Referrals, aliases, paged results, substring and approximate filters, and SASL.
Substring filters in particular are absent on purpose: they ask the server to do
open-ended work on behalf of whoever opened the connection.

Group entries are neither readable nor writable. `memberOf` is published on a
person, but there is no `ou=groups` subtree to search or modify — writing group
membership means writing the group's `member` attribute, and a subtree that could
be written and not read would be incoherent.
