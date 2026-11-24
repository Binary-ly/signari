# LDAP

## Introduction

Some older software can check a password only by asking a company directory. It
speaks the Lightweight Directory Access Protocol ([LDAP](glossary.md#ldap)), and
asks the directory whether a username and password are right. That request is
called a "bind". No browser is involved: Ada types her password into the
application itself.

Signari can answer those binds as an LDAP server. Software written for a
directory can then check the people Signari keeps, with the same password and the
same limits as the sign-in page. [Which protocol do I
need?](protocols-explained.md#ldap) explains LDAP in plain words.

The LDAP listener is off until you give it an address. You configure it with
environment variables when you start Signari.

> [!NOTE]
> This page is about Signari acting as a directory. To read people from an existing
> LDAP directory into Signari, see [LDAP as a source](ldap-source.md).

## Turn on the LDAP listener

To start Signari with the LDAP listener on port 636, give it the listener's
address, the base of the directory and the organisation it serves:

```sh
SIGNARI_LDAP_ADDR=0.0.0.0:636 \
SIGNARI_LDAP_BASE_DN="dc=example,dc=com" \
SIGNARI_LDAP_ORG_ID=<org-uuid> \
signari serve -addr :443 -tls-cert cert.pem -tls-key key.pem
```

The listener is off unless `SIGNARI_LDAP_ADDR` is set. It is a second place where
passwords are checked, and one nobody asked for should not be listening.

People bind as `uid=<username>,<base-dn>`. A "DN", or distinguished name, is the
full name of an entry in the directory. The "base DN" is the name at the top of
the directory, which is `dc=example,dc=com` in this example.

## What this is, and what it deliberately is not

Signari's LDAP listener is a **compatibility shim**. It offers bind and search, so
that software written against a directory can authenticate people who live in
Signari.

Since August 2026, it can also be **written to**, with `add`, `modify`, `delete`
and `modify DN` (RFC 4511 §4.6–§4.9), against an explicit schema. That is **off by
default**, and takes two decisions to turn on. See [Writes](#writes) below.

It is still not a directory. There is no replication, no directory information
tree (DIT) structure rules, no aliases and no subordinate entries. The tree is
flat, and holds `person` entries. Everything outside that is **refused**, not
stubbed, because a half-implemented directory is one somebody eventually depends
on.

## The rule the CVE record points at

A published vulnerability, **CVE-2017-14623**, against the go-ldap library, says:

> "an attacker may be able to login with an empty password. This issue affects an
> application using this package if these conditions are met: (1) it relies only
> on the return error of the Bind function call to determine whether a user is
> authorized... and (2) it is used with an LDAP server allowing unauthenticated
> bind."

RFC 4513 §5.1.2 names that case: a simple bind carrying a DN and an **empty
password** is an *unauthenticated* bind. The person supplied a name, and proved
nothing. Applications ask "did the bind return an error?", and read `nil` as
"authenticated". So a server that answers success here hands every one of them a
bypass.

Empty passwords are refused. There is no configuration option to allow it. The
refusal happens **before** the credential checker is reached, so it is part of
the structure, not a comparison that happened to fail.

This was verified with `ldapwhoami`, not with Signari's own client:

```
$ ldapwhoami -x -H ldaps://... -D "uid=alice,dc=signari,dc=test" -w ""
ldap_bind: Invalid credentials (49)
    additional info: a bind with an empty password authenticates nobody
                     (RFC 4513 section 5.1.2)
```

## Other decisions

**Anonymous search is off by default.** An "anonymous" search is one made with no
bind. An anonymous search endpoint publishes a directory of people to anyone who
can reach the port. That is how internal address books end up in breach dumps.
`SIGNARI_LDAP_ANONYMOUS_SEARCH=1` turns it on deliberately.

**A bound person sees only their own entry.** Binding proves a password, and that
is all it proves. Reading every name, address and group in the organisation is a
separate grant, so it goes to a group. This setting names the group:

```sh
SIGNARI_LDAP_SEARCH_GROUP=directory-readers
```

Members of that group can search the whole directory. They are usually the
"service accounts" that applications bind as to look people up: accounts that a
program uses, not a person.

Everyone else can search, but the only entry they get back is their own. Reading
another person's DN directly returns nothing, and the answer is the same whether
or not that person exists. Members of `SIGNARI_LDAP_WRITE_GROUP` can search as
well, since they can already rename and delete anyone. When anonymous search is
on, every connection sees everything, because nothing is gained by limiting bound
people then.

An LDAP outpost, a Signari program that serves LDAP away from the database, takes
its search group from its registration instead. You set it with
`signari outpost search-group`, and the core enforces it. See
[outposts](outposts.md#what-an-outpost-token-is-worth).

Before this, any account that could bind could list the directory. If an
application's service account searches for other people, add it to the search
group. Otherwise its searches will come back with only its own entry. The same
setting applies to an LDAP outpost, which reads it from its own environment.

**Group membership is read on every operation, not at bind.** A client keeps a
connection open for as long as it likes. So each search and each write looks the
bound person up again. Once someone is removed from the search group, their next
search on the same connection returns only their own entry.

Once someone is removed from the write group, their next write is refused with
`insufficientAccessRights`. A deactivated person gets nothing back. Until October
2026, both groups were taken from the bind. A connection opened before the change
kept listing or rewriting the directory until it was closed.

**No `userPassword` attribute is ever returned**, at any value. Some directories
return a hash, and some return a placeholder. Both teach applications to compare
credentials themselves. That is how a password ends up compared with `==` in
somebody else's code.

**`compare` is refused.** It answers "does this attribute equal this value?".
Against a password attribute, that is a guessing "oracle": something that answers
yes or no to each guess, with no failed-sign-in counter anywhere near it.

**StartTLS is refused; LDAPS is supported.** "StartTLS" upgrades a plain
connection to an encrypted one partway through. "LDAPS" is LDAP over Transport
Layer Security ([TLS](glossary.md#tls)) from the first byte. A server that answers
success to StartTLS without really upgrading the connection has told the client
the channel is protected. The client then sends a password over it in the clear.

Supplying `-tls-cert` makes the LDAP listener LDAPS. Without one, the engine
**refuses to start** unless `SIGNARI_LDAP_INSECURE=1` asks for plaintext by name.
That is the same rule as for the Admin API and the LDAP outpost. The engine used
to warn and listen anyway. Some deployments ended TLS in front of the engine, and
so started it with no certificate. Each of them took every directory password in
clear, with one log line to show for it.

**A failed re-bind drops the identity.** A connection that stayed bound as its
previous identity would let a client authenticate once. The client could then
keep the session while claiming to be someone else.

**An unknown person and a wrong password are indistinguishable**, in both the
message and the timing. The dummy verification runs even when no person was
found. Otherwise the port would be an oracle for which accounts exist, open to
anyone who can reach it.

**A filter this directory cannot evaluate matches nothing, negated or not.** A
search "filter" says which entries to return. A filter is TRUE, FALSE or
Undefined, and only TRUE returns an entry. An attribute it does not know, a
matching rule it does not recognise or a malformed substring is Undefined. It
stays Undefined through a NOT. Until October 2026, such a filter was FALSE, so
`(!(shoeSize=12))` returned the entire directory.

**Filters.** These kinds of filter are evaluated:

- Equality.
- Presence.
- Substrings, such as `(cn=al*)`, with at most eight parts, none of them
  overlapping.
- `>=` and `<=`, which compare the case-folded value in byte order.
- `~=`, treated as equality, as RFC 4511 says where approximate matching is not
  supported.
- Extensible matches.

An extensible match names its rule by name: `caseIgnoreMatch` or
`caseExactMatch`, or their IA5 forms. A rule given by object identifier (OID) is
not recognised. `:dn:` also tries the entry's DN. A value is matched as its BER
(Basic Encoding Rules) encoding carried it, so a `*` a client escapes is a
character. Beginning-of-name searches on `uid` and `mail` are asked of the
database. Other substrings are read a page at a time and checked here.

**Groups are entries.** Each group with somebody active in it is a `groupOfNames`
at `cn=<name>,ou=groups,<base>`, with a `member` for each active person. That is
where a person's `memberOf` has always pointed. A search of `ou=groups`, or a
subtree search of the base, finds them, paged like people.

Whoever can read the directory can read the groups. Anyone else has their groups
on their own entry. An empty group is not published, since `groupOfNames` must
have a member, and the alternative is a member who is not one. Through an outpost,
groups are read from the core in the same way.

**The schema is published.** The "root DSE" is the entry a client reads first, to
learn what a directory supports. It names `cn=Subschema` as `subschemaSubentry`.
A base search of that entry needs no bind. It returns `attributeTypes`,
`objectClasses` and `ldapSyntaxes`: what this directory really holds,
single-valued where it is, not what the standard allows.

**Everybody can be found, and a short list says so**. A filter on `uid`, `mail`,
`cn` or `memberOf`, alone or in an AND or OR, is asked of the database. So one
person among a hundred thousand is one query. Anything else is read a page at a
time and checked here. That is slower, and equally right, since the database only
ever narrows and this check decides.

A search returns 500 entries at most. Past that, it answers
`adminLimitExceeded`, or `sizeLimitExceeded` for a limit the client set, with the
entries so far. It never answers success. To read more, use the RFC 2696 paged
results control (`ldapsearch -E pr=500/noprompt`), which the root DSE advertises.

A page carries on from its last entry, however far in that is. A cookie this
directory did not issue is a `protocolError`. Until October 2026, the directory
read the first 500 people and filtered those, so nobody after them could be found
by any search.

**The search base and scope are honoured.** Every person is a direct child of the
base DN, so the scope works like this:

- A one-level search reaches people only from the base DN.
- A subtree search reaches everyone from the base DN, or one person from that
  person's DN.
- A search based anywhere else returns nobody. `ou=groups,…` reaches the groups
  and no person.

Until October 2026, any one-level or subtree search under the base returned the
whole directory, wherever it was based.

**A critical control is refused.** A request "control" asks the directory to
carry out an operation in a particular way, such as sorting its results. This
server applies no request controls. So an operation carrying one marked critical
is not performed, and is answered `unavailableCriticalExtension` (12), as RFC 4511
§4.1.11 requires. A non-critical control is ignored.

Critical controls used to be ignored too. So a client that made, say, a
server-side sort a condition of its search got the search without it.

**One organisation per listener, stated explicitly.** LDAP has no way to name an
organisation, which some products call a "tenant". The DN is the only input, and
the client chooses it. Inferring the organisation from data an attacker controls,
and getting it wrong, means binding someone against another organisation's
directory. `SIGNARI_LDAP_ORG_ID` is required unless the database holds exactly one
organisation.

**Binds go through the same credential path as the sign-in form**. They use the
same query, including its status check, the same Argon2 parameters and the same
throttling. An LDAP front end with its own quiet credential path is a way around
every control the rest of Signari has.

### The guessing budget, and what a client sees when it is spent

Failed binds are counted on two keys: **20 per address per 5 minutes** and **30
per account per 15 minutes**. Both are the *same buckets the sign-in form uses*,
not a second allowance of the same size. Two doors onto one credential draw down
one budget, or the number describes neither door.

**Only failures are charged.** A correct bind costs nothing. So a mail server, or
a virtual private network (VPN) concentrator that binds on every request, is never
throttled by its own success. The limits expire by themselves. There is no
lockout, and no administrator action is needed to clear one.

**The place is taken before the password is verified**. Each bind claims its
place in both budgets first, and hands it back unless the password turns out to
be wrong. The budgets used to be read before the Argon2 verification, and only
charged after it. So every bind that arrived while others were still being
verified read a count under the limit. A parallel burst was hashed in full before
the first failure was counted.

A burst of sixty wrong binds now produces thirty verifications and thirty `busy`
answers. Binds in flight count while they are in flight. So a single client making
more simultaneous binds than the limit is told `busy` for the rest.

**A bind has ten seconds**, the wait for the shared hasher included. Past that, it
answers `busy` and the client retries. The verification waits for the same hasher
slots as the sign-in form. Without a deadline, a flood of binds queued there
indefinitely, ahead of people signing in at the browser.

A bind refused for throttling answers **`busy` (51)**, not `invalidCredentials`
(49). Every other failure is deliberately indistinguishable: no such person, a
wrong password, or a deactivated account. Telling them apart would be an oracle
for which accounts exist, for anyone who can open the port.

Throttling is the exception, for two reasons. Its answer is identical whether or
not the account exists, so it discloses nothing. And reporting it as a bad
password sends an administrator to rotate a credential that was correct. The
guessing run that really spent the budget would stay invisible.

### A password alone, and a second factor

A bind has one credential field. Remote Authentication Dial-In User Service
([RADIUS](radius.md)) with the Password Authentication Protocol (PAP) is the same,
and so are the outposts (see [outposts](outposts.md)). So a person with an
authenticator can put their code after their password, as `password;123456`: six
to eight digits after the last semicolon.

The code is held to what the sign-in form holds a code to. It is spent once, and a
wrong one is charged to the authenticator and to the person's budget. A code that
is given has to be right, even where the password alone would have done. A
password that really does end that way still works.

An emailed or texted code cannot be used. Each is taken only for the sign-in it
was sent for, and nothing here sends one. A texted code was taken until November
2026.

Each organisation decides what happens when the person binding is someone its
sign-in page would ask for a second factor. Under the built-in flow, that is
anybody who has one enrolled. Under an unconditional `mfa` stage, it is everybody.

A registered security key or passkey has counted as enrolled since October 2026,
when the sign-in page began asking for one after a password. So a person who has
registered a passkey is refused a password-only bind under `refuse_when_mfa`. The
setting is `password_only_binds`:

| `password_only_binds` | A correct password from such a person |
|---|---|
| `refuse_when_mfa` | refused unless a code came with it, answered as `invalidCredentials` (49) like any other failure, and audited as `login.failed` with reason `second_factor_required`. **The default for organisations created since migration 0128** |
| `allow` | accepted. The value every older organisation keeps until changed, so an upgrade does not stop a VPN working |

Set it with `signari instance password-binds -org <id> -binds refuse_when_mfa`.
`signari doctor` names every organisation still set to `allow` that has an LDAP or
RADIUS listener or outpost. Under `allow`, a sign-in page that demands a second
factor sits next to a port that does not. A stolen password then only has to be
typed into a VPN prompt.

The refusal is checked **after** the password. So the timing and the answer are
the same as for a wrong password, and a guesser learns nothing from it. It is
**not charged** to the guessing budget, because the password was right. A client
retrying it in a loop would otherwise spend the person's budget at the sign-in
page as well. If whether the person has a second factor cannot be read, the bind
is refused.

Service accounts that bind to the directory should have no second factor enrolled,
or `refuse_when_mfa` refuses them too. Carrying a code with the password (a
`;123456` suffix, or a RADIUS Access-Challenge) is the full answer. It is not
built yet. When it is, this setting will decide only what happens without one.

## Verified against

The listener is tested with `ldapsearch` and `ldapwhoami` from OpenLDAP, and with
`go-ldap` in the test suite. These are separate implementations, by different
authors. Testing Signari with its own client would only prove that it agrees with
itself. And agreeing with itself is what a protocol bug looks like from the inside.

One bug came from that. A bind DN of `uid=alice` with **no base suffix at all** was
accepted. The suffix check only ran when there was something after the leading
relative distinguished name (RDN). Validation that can be bypassed by leaving out
the thing being validated is not validation.

## Writes

To allow writes to the directory, name the group whose members may write:

```sh
SIGNARI_LDAP_WRITE_GROUP=directory-admins
```

**Two decisions, not one.** The variable above names *who*, and the engine only
builds a writer at all when it is set. A read-only deployment behaves exactly as it
did before writes existed, down to the result code.

**Empty means nobody.** That is the "fail-closed" reading, which refuses when in
doubt. It is right here for the same reason the Shared Signals
([SSF](ssf-caep.md)) stream's `Allows` field takes it. Reading an unset list as
"everybody" is how a half-made configuration becomes a live grant. This particular
grant is the ability to rewrite the directory, and then bind as anybody in it.

It is a **group**, not a list of DNs. So the people who hold it appear in their own
`memberOf`, and are managed with `signari group member` like every other
privilege. Startup logs a warning naming the group. Otherwise the only evidence
would be an environment variable that nobody may have set deliberately.

A refusal distinguishes the two cases. It is `unwillingToPerform(53)` for a
read-only directory, and `insufficientAccessRights(50)` for a bound identity
outside the group. Those send an administrator to completely different places.
Neither tells an attacker anything they could not learn by trying with any
account.

### The schema

`internal/ldapd/schema.go` is an explicit table. Anything not in it is answered
`undefinedAttributeType(17)`, not quietly accepted and dropped:

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
all. The shim published `cn: <username>`, and Signari had never stored a display
name. So an `add` carrying `cn: Alice Okonkwo` would have been accepted and
dropped.

And `sn` is a MUST attribute of a class **every entry here has always declared**.
That means every entry this directory ever published was schema-invalid. Nobody
noticed, because almost nothing validates a search result against a schema it did
not fetch. It surfaced from the other direction: working out what an `add` would
have to require.

Rows that predate the column have no surname, so the read side derives one from
the display name. That is a guess, and is labelled as one in the code. The
alternative is publishing a `person` with no `sn`, which a schema-aware client is
entitled to reject.

### Result codes

Result codes are as specific as the specification allows, because a directory
client acts on them:

- `entryAlreadyExists(68)` tells a provisioning run to move on.
- `constraintViolation(19)` tells it to fix the data.
- `notAllowedOnRDN(67)` tells it to use `modify DN`.

A shim reaching for one code collapses everything to `unwillingToPerform`. That
turns each of those into "something went wrong, retry forever".

### Modify is atomic, and resolved before it is applied

RFC 4511 says, in §4.6: *"The entire list of modifications MUST be performed in
the order they are listed as a single atomic operation ... the client may expect
that no modifications of the DIT have been performed if the Modify Response
received indicates any sort of error."*

So the changes are folded into a **final state** against the entry as it stands,
and the store applies that state in one transaction. Applying them one at a time
against the database would make a failure halfway through a partial write. That
is the one outcome §4.6 promises cannot happen.

The MUST attributes are checked on the **result**, not per change. A request that
deletes `sn` and adds it back is legal. One that only deletes it is not.

Deleting `userPassword` removes the credential and keeps the account. It is
refused with `constraintViolation` unless the entry holds at least two passkeys.
Otherwise nothing would be left to sign in with (see [signing in without a
password](passkey-signals.md#signing-in-without-a-password)).

### `delete` deletes

It does not deactivate. A directory `delete` that quietly deactivates is the
failure this whole design is against. The client asked for the entry to be gone,
a later search would not find it, and the row would still be there.

The person's sessions are ended first, in the same transaction. So each
application they signed in to is sent a Back-Channel Logout notice, with `reason`
`user_deleted`. Letting the delete cascade the sessions away would remove the list
of applications to tell before anyone was told.

It is **not** `signari erase subject`. Deleting removes the row and everything
cascading from it. It does not destroy the subject's data-encryption key, so
ciphertext already written to backups stays readable. Crypto-shredding, destroying
that key, is a separate and deliberate act. See [erasing a subject](erasure.md).

### `modify DN` and `deleteoldrdn`

RFC 4511 §4.9 says that with `deleteoldrdn` FALSE, "the attribute values forming
the old RDN will be retained as non-distinguished attribute values of the entry".

`uid` is single-valued here, so that cannot be represented. It is **refused**
(`constraintViolation`), not ignored. A server that accepted FALSE and dropped the
old value anyway would have done the one thing the flag exists to prevent.

`newSuperior` is refused for anything but the base DN. This directory is flat, so
the only superior that exists is the naming context. §4.9 specifies
`noSuchObject` with `matchedDN` for exactly that case.

### Every write is audited, inside its own transaction

A directory write absent from the trail is one nobody can answer for. Committing
the change while the record of it failed would be exactly that. Deletion is
audited **before** the row goes, because afterwards there is no subject for the
event to name.

The entry is named by its subject ID, and the bound account by `actor_id`. A
rename records that the username moved, not what to. Until October 2026, every row
carried both usernames in its detail, in plaintext inside the hash chain, where
erasure cannot reach. A test now fails on any audit event whose detail names a
person.

A password set through this path gets **its own event**, separate from "the entry
was modified". Somebody with directory write access can set any password, then
bind as that person. It is the most consequential thing this interface can do, and
the thing an investigation looks for.

A write **refused** because the bound account is not in the write group is audited
too. It is audited as `ldap.write_refused`, with the operation (`add`, `modify`,
`delete`, `modify_dn`), by the account's subject ID. Until October 2026, it was a
log line naming the account. That is where an attempt to change the directory
without permission would have been looked for, and not found.

Passwords go through the **same policy** as the sign-in form. A directory write is
the one path where a password arrives with nobody at a form to be told what is
wrong with it. That makes it the most likely way to seed an estate
with weak credentials.

### Writes are in-process only

The LDAP **outpost** has no write path back to the engine, and refuses everything
with `unwillingToPerform`, as before. Adding one would mean putting directory
changes on the outpost API, which is deliberately a password-verification oracle
and nothing more.

## POSIX accounts

A host can take its accounts from this directory, through the System Security
Services Daemon (SSSD) or anything else that reads RFC 2307. To publish POSIX
(Portable Operating System Interface) accounts, set:

```sh
SIGNARI_LDAP_POSIX=1 SIGNARI_LDAP_POSIX_HOME=/home/{username} SIGNARI_LDAP_POSIX_SHELL=/bin/bash
```

People then also carry `posixAccount`, with `uid`, `uidNumber`, `gidNumber`,
`homeDirectory`, `loginShell` and `gecos`. Groups carry `posixGroup`, with
`gidNumber` and `memberUid` beside `member`. Nothing changes for a directory that
does not ask. All of it is read-only here.

The host still binds with a search account, because a person who only binds sees
their own entry. So put that account in the group that `SIGNARI_LDAP_SEARCH_GROUP`
names.

**Every person and group has a number from when they are made.** It comes from a
sequence that never goes back. So deleting somebody frees nothing, and a new
employee can never be given an erased one's files. Numbers start at 2000000000,
well above a host's own accounts. The sequence is the deployment's, so an
organisation comparing two of its own numbers can estimate how many accounts were
made between them.

**A number you already have can be kept.** Suppose you are moving from a directory
whose hosts have files owned by uid 1234. Set `posix_uid` on
`PATCH /admin/users/{userID}`, and `posix_gid` on `PATCH /admin/groups/{groupID}`.
They take 1000 to 1999999999. Nothing allocated can land there, and below it are a
host's own accounts, root among them. Two people in an organisation cannot share
one.

A restore from a backup restores the sequence too, so numbers given out after that
backup can be given out again. A host that kept their files should be treated with
the same care as the people it restored.

A person's `gidNumber` is their own number, the group private to them. This
directory publishes no such group, so `id` shows the number where a name would
be. Groups they belong to come through `memberUid`, and show normally. A group
with nobody in it is not published, here as anywhere in this directory.

## Not implemented

Referrals, aliases, every request control but paged results, and the Simple
Authentication and Security Layer (SASL) are not implemented.

Group entries are read-only. Membership is managed where groups are, and a
directory-shaped write to it would be a second way in.
