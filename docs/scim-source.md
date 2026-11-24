# Receiving SCIM

## Introduction

Some organisations keep their people in another system, such as Microsoft Entra
ID, and want that system to manage their accounts in Signari. When somebody joins
or leaves there, the change should reach Signari without anybody typing it again.

Another system that holds your people can create, change and deactivate them in
Signari over the System for Cross-domain Identity Management
([SCIM](glossary.md#scim)). That system is the "upstream", and Signari applies
the changes it sends.

You register an upstream as a source with `signari scim-source add`, or through
the [Admin API](admin-api.md).

## Register a source

Registering an upstream as a source gives it an address and a token:

```
SCIM base URL : <issuer>/scim/v2
bearer token  : <shown once, stored only as a SHA-256 hash>
```

`signari scim-source add` registers an upstream and prints that token. The
Admin API does the same at `POST /admin/organizations/{orgID}/scim-sources`, and
takes one out of service with `PATCH .../scim-sources/{slug}`. See
[the Admin API](admin-api.md).

## PATCH is where every implementation goes wrong

A PATCH request changes part of a record. RFC 7644 §3.5.2 defines a small
operation language for it, and the two upstreams that matter emit different
dialects of it.

Handling only the dialect you tested against fails **silently**. A PATCH that
changes nothing still returns 200, and the upstream records a successful sync.

All of these are accepted, and each is a shape seen in the wild:

```json
{"op":"replace","path":"active","value":false}
{"op":"replace","value":{"active":false}}                 // Entra: no path
{"op":"Replace","path":"active","value":false}            // Entra: capitalised
{"op":"replace","path":"active","value":"False"}          // Entra: a STRING
{"op":"replace","path":"urn:ietf:params:scim:schemas:core:2.0:User:active", ...}
```

The fourth is the one that causes real damage. Parsed with the ordinary rules of
most languages, a non-empty string counts as true. So a **deactivation is
applied as an activation**. The person who has left the company keeps their
account, and the upstream shows a green tick.

A value that is neither true nor false is **refused**, never guessed. The two
possible guesses are "keep their access" and "remove it".

## externalId, never userName

`externalId` is the upstream's immutable identifier, and the only thing matched
on. `userName` and email both change when somebody marries. Matching on either
turns a rename into a departure plus an arrival. One account is deactivated, one
is created, and the person is locked out of everything they owned.

A create without `externalId` is refused, with that reasoning in the message.

## A source never takes over an administrator

A create whose address matches an existing local account adopts that account,
rather than duplicating it. That covers somebody who signed up before
provisioning was turned on.

There is one exception. A person who **may act as other people** is not adopted,
and the create is answered `403`. That is a member of a group that may
[impersonate](impersonation.md). The same applies to changing such a person's address through
a PUT or PATCH. Resending the address they already have is fine, and so is
switching them off.

A source is trusted to describe the people it manages. An administrator it
adopted would have an address the upstream could change. That is one password
reset away from an account that may become anybody. Every refusal is recorded
as `scim.privileged_refused`.

## Retries are free

A create sent twice makes one person. This was verified live: two identical
creates, one link in the database, and the same id both times.

## DELETE means deactivate

By default, a DELETE of a person deactivates them, and keeps their account.

`-on-deactivate delete` is available, and prints a warning saying what it costs.
Under it, a person who may act as other people is still only deactivated. The
upstream's intent, that they stop getting in, is met, and so is the removal of
their sessions. The answer is `204`, and the trail records
`scim.privileged_kept`.

Removing an administrator's account outright is left to an administrator of this
deployment. Refusing the DELETE instead would leave a departed administrator
signed in.

A DELETE of a person or group that is not there answers `404`, as RFC 7644 §3.6
requires of a resource already deleted. So a retried deprovisioning learns it is
done. Until October 2026 it answered `204`, as if it had removed somebody.

## Deactivation ends sessions

A deactivated account with a live session is still a signed-in person. So every
request that deactivates ends the person's sessions in the same transaction.
That is a PUT, PATCH or re-sent POST carrying `"active": false`, or a DELETE. A
DELETE under `on_delete = delete` ends them too, before the row goes.

Each application the person signed in to is sent a
[back-channel logout](glossary.md#back-channel-logout) notice, with `reason`
`user_deactivated` or `user_deleted`. Receivers of the Continuous Access
Evaluation Profile ([CAEP](glossary.md#caep)) get `session-revoked`. The refresh
tokens issued under those sessions stop working, and a proxy cookie stops
passing [forward auth](forward-auth.md) at once.

## Groups

`/Groups` is the half an enterprise actually connects SCIM for. People would
arrive on first sign-in anyway, but **membership would not**. And membership is
what every authorization rule reads.

These are the group endpoints:

```
GET    /scim/v2/Groups?filter=displayName eq "Engineering"
POST   /scim/v2/Groups
GET    /scim/v2/Groups/{id}
PUT    /scim/v2/Groups/{id}
PATCH  /scim/v2/Groups/{id}
DELETE /scim/v2/Groups/{id}
```

### The failure this is shaped around

Almost nothing creates a group and leaves it alone. What arrives, continuously,
is membership churn: one PATCH for each person joining or leaving. And a
`remove` whose dialect a server does not understand, treated as an unsupported
path, returns **200**.

The upstream records the removal as done, and never sends it again. The person
keeps the group and everything it grants, permanently, while the upstream's own
console shows them as removed. Nothing anywhere is in a state that looks wrong.

So a member operation that cannot be read is a **400**. A refused PATCH is
retried, and a misread one is not.

### The dialects

Upstreams say "remove this member" in several dialects. Each of these is read as
the removal of that one member, and none of them empties the group:

```json
{"op":"remove","path":"members[value eq \"abc-123\"]"}
{"op":"remove","path":"members[value eq \"abc-123\"].value"}
{"op":"Remove","path":"members","value":[{"value":"abc-123"}]}   // Entra: in the value, capitalised
```

Two more distinctions are silent when wrong:

- **`replace` on `members` is not `add`.** It sets the list, so everybody absent
  is removed. Read as an add, a departed employee stays in the group while the
  upstream reports the sync complete.
- **`PUT` with no `members` means no members**, unlike `PATCH`, where an absent
  field means "leave it alone". That is what distinguishes the two verbs, and
  treating them alike makes a group impossible to empty.

### displayName versus the name in a token

`core.groups.name` is constrained to `^[a-zA-Z0-9._-]{1,64}$`. A group's name
travels through JSON arrays, [SAML](glossary.md#saml) (Security Assertion Markup
Language) attribute values, and [LDAP](glossary.md#ldap) (Lightweight Directory
Access Protocol) filters. In each of them, a space or a quote means something
else. Upstream display names routinely contain both, such as
"Engineering Team" and "Finance & Legal".

Matching is on `externalId` alone. Matching on `displayName` would make a rename
look like the deletion of one group and the creation of another, revoking
everything the first one granted.

### A source manages only the groups it creates

If a `POST /Groups` derives a name that a group in the organisation already
has, the request is refused with `409 uniqueness`. The existing group might have
been made by an administrator or by another source, or have members who may
impersonate.

Each group has at most one source, and a group a source manages cannot be given
impersonation. Both rules are enforced by the database, so they also hold for
any other writer:

- `signari group impersonation -grant` on a group a source manages is refused;
- a source cannot be linked to a group that may impersonate.

The reason is the one [directory sync](directory-sync.md) already follows.
Whoever administers the upstream decides who is in its groups. Before this,
sending a matching display name took the existing group over. The upstream's
people went in, everyone else was removed, and the group kept everything it
already granted.

If you want an upstream group to reach an application, let the source create the
group. Then [release](groups.md#release-is-an-allow-list-per-application) the group to
the application.

### Two deliberate asymmetries with /Users

People and groups differ in two deliberate ways:

| | Users | Groups |
|---|---|---|
| `DELETE` | **deactivates** | **deletes** |
| a member/user we do not know | — | **400 with the reason** |

Deleting a person destroys the audit trail of everything they did. That is the
thing you most need about somebody who has recently left. A group holds no
history of its own: who was added, and when, lives in the audit events. And a
deprovisioned group that lingers keeps granting whatever it grants.

A member naming a person this source never provisioned is a 400 rather than
a 500. An upstream retries a 500 unchanged forever, and acts on a 400.

## What is not implemented, and therefore not advertised

`ServiceProviderConfig` is where a SCIM server says what it supports. It says
these are not:

| | |
|---|---|
| sort, etag, changePassword | `ServiceProviderConfig` says `supported: false` |

Advertising a capability that 404s is the failure this project sweeps for. That
is why `/Groups` entered `/ResourceTypes` only when it was implemented. It is
also why `ResourceTypes` now counts its own list, rather than carrying a number
beside it that can drift.

A list takes a filter in RFC 7644's grammar: `and`, `or`, `not`, brackets, and
every attribute comparison of its Table 3, over what the two resources return.
`totalResults` counts what matched. These attributes can be filtered on:

| Resource | Attribute | Compared | Operators |
|---|---|---|---|
| Both | `id` | as an id | `eq` `ne` `pr` |
| Both | `externalId` | as stored | all |
| Both | `displayName` | ignoring case | all |
| Both | `meta.created`, `meta.lastModified` | to the second | `eq` `ne` `gt` `ge` `lt` `le` `pr` |
| User | `userName`, `emails.value` | ignoring case | all |
| User | `active` | as a boolean | `eq` `ne` `pr` |
| User | `emails` | | `pr` |
| Group | `members` | | `pr` |
| Group | `members.value` | a member's id | `eq` `pr` |

`/Schemas` says the same: `externalId` is `caseExact`, because an upstream's
identifier is opaque, and two that differ by case are two people. An attribute
can be written with its schema. A person with no address is not equal to any
address, and `eq null` finds them.

`id eq` something that is not one of ours finds nobody, since an upstream may
hold ids from elsewhere. `co`, `sw` and `ew` take the value as text, so `%` is a
percent sign.

Anything else is a **400** with `scimType` `invalidFilter` (RFC 7644 Table 9),
not an ignored parameter. Ignoring an unrecognised filter returns the whole
directory, and a caller reading the first result would then match the wrong
person. That covers:

- an attribute Signari does not store, even negated, because read as absent
  `not (nickName eq "x")` would match everybody;
- a value of the wrong type;
- `gt` on a boolean;
- a value path such as `emails[type eq "work"]`;
- a filter of more than 256 terms.

A value is JSON, so a string is quoted, and `userName eq "a" or userName eq "b"`
is two comparisons. It used to be read as a search for one person with an odd
name, which matched nobody and invited a duplicate create.

## Bulk

`POST /scim/v2/Bulk` takes up to 1,000 operations in 4 MiB, the limits
`ServiceProviderConfig` publishes. Past either, it answers **413** naming it.

Each operation is a POST to `/Users` or `/Groups`, or a PUT, PATCH or DELETE of
one by id. It goes through what its single request would: the same validation,
the same audit record, the same refusals.

- A POST needs a `bulkId`. `"bulkId:qwerty"` anywhere else in the request is
  replaced by the id it made: a group's member, a `manager.value`, a path. Only a
  whole string is a reference.
- Operations run in the order given, except that one naming a `bulkId` not yet
  made waits for it. References that wait on each other answer **409**, as does
  one naming a POST that failed. One naming nothing in the request answers
  **400**.
- A failure is that operation's. The rest carry on, and the job answers **200**
  with a line for each, in the order asked. **What succeeded stays**: this is
  not a transaction, as the RFC requires. `failOnErrors` stops after that many
  errors, and an operation that never ran has no line.
- `version` is ignored, since ETags are not supported.

## The enterprise extension

`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User` is kept in the
organisation's own [attributes for people](admin-api.md#attributes-of-people), so declare the ones you want
with `PUT /admin/organizations/{orgID}/attributes`:

| Extension attribute | User attribute |
|---|---|
| `employeeNumber` | `employee_number` |
| `costCenter` | `cost_center` |
| `organization` | `organization` |
| `division` | `division` |
| `department` | `department` |
| `manager.value` | `manager` |

Declaring is the whole decision. As for a value set any other way, the
declaration says:

- whether a value is personal, and so sealed under the person's key and
  destroyed with it;
- what type it has;
- through a claim mapper, whether it reaches a token.

`/Schemas` and `/ResourceTypes` offer the attributes this organisation declares,
and no others.

A POST, PUT or PATCH can carry the extension. A PATCH can write it in any of the
ways upstreams do. That is a full path, a pathless object of full names, a
nested object, or the extension whole. A manager can be an id, `{"value": id}` or an
array of one, and its `displayName` is not kept. `remove`, `null` and an empty
string clear a value.

- An attribute that is not declared is **not stored and not refused**. The
  request succeeds, as it does for a phone number, and the log names it. Nobody
  has decided anything about such a value, so it has no erasure story.
- A value that does not fit the declared type, or that would clear a required
  attribute, is a **400** with `scimType` `invalidValue`. Nothing in the request
  is applied.
- A PUT with the extension replaces it, so what it leaves out is cleared. A PUT
  without it changes nothing, since a client that does not send it may not
  understand it.
- An upstream cannot change the attributes of a person who may act as other
  people: a **403**, as for their address. Resending what they already hold
  succeeds.
- The audit record names which attributes moved, never their values.
- These attributes cannot be filtered on: a personal value is sealed, so a query
  cannot read it.

## Three bugs a running engine found, none of them in SCIM

Running it against the real schema, in August 2026, found mistakes the compiler
cannot see, because SQL in a string is not type-checked:

- **`display_name` on `core.users` did not exist.** A later change added it, for
  the directory's `cn`. Names from a source live on the link row,
  as `core.directory_links.remote_name` already does. A name is a fact one
  upstream asserts, and two upstreams asserting different names is a conflict
  with no correct resolution.
- **`user_handle` is NOT NULL with no default**, so every insert site must
  generate the 64-byte WebAuthn handle.
- **`status = 'inactive'` is not a valid status.** The constraint allows
  `active | deactivated | locked`. "inactive" is the obvious English word, and
  not one of the three.

And the fourth, which was **not** in new code at all:

- **`core.sessions.revocation_reason = 'admin'`** in `internal/directory/apply.go`.
  The constraint requires `admin_revoke`. That statement failed, so the whole
  transaction rolled back. So **the directory sync's deactivation never
  happened**: a departed employee stayed active *and* stayed signed in.

  It passed its tests because none of them gave the person a session, so the
  UPDATE matched zero rows and its values were never checked. The test now
  creates a session before the deactivation, and fails with the old value
  restored.
