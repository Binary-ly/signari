


```
SCIM base URL : <issuer>/scim/v2
bearer token  : <shown once, stored only as a SHA-256 hash>
```


## PATCH is where every implementation goes wrong

RFC 7644 §3.5.2 defines a small operation language, and the two upstreams that
matter emit different dialects of it. Handling only the dialect you tested
against fails **silently**: a PATCH that changes nothing still returns 200, and
the upstream records a successful sync.

All of these are accepted, and each is a shape seen in the wild:

```json
{"op":"replace","path":"active","value":false}
{"op":"replace","value":{"active":false}}                 // Entra: no path
{"op":"Replace","path":"active","value":false}            // Entra: capitalised
{"op":"replace","path":"active","value":"False"}          // Entra: a STRING
{"op":"replace","path":"urn:ietf:params:scim:schemas:core:2.0:User:active", ...}
```

The fourth is the one that causes real damage. Parsed with the ordinary rules of
most languages, a non-empty string is truthy — so a **deactivation is applied as
an activation**. The person who just left the company keeps their account and
the upstream shows a green tick.

A value that is neither true nor false is **refused**, never guessed. The two
possible guesses are "keep their access" and "remove it".

## externalId, never userName

`externalId` is the upstream's immutable identifier and the only thing matched
on. userName and email both change when somebody marries; matching on either
turns a rename into a departure plus an arrival — one account deactivated, one
created, and the person locked out of everything they owned.

A create without `externalId` is refused, with that reasoning in the message.

## A source never takes over an administrator

A create whose address matches an existing local account adopts that account
rather than duplicating it. That covers somebody who signed up before
provisioning was turned on. There is one exception: a person who **may act as
other users** (a member of a group that may impersonate) is not adopted, and
the create is answered `403`. The same applies to changing such a person's
address through a PUT or PATCH. Resending the address they already have is
fine, and so is switching them off.

A source is trusted to describe the people it manages. An administrator it
adopted would have an address the upstream could change, and that is one
password reset away from an account that may become anybody. Every refusal is
recorded as `scim.privileged_refused`.

## Retries are free


Verified live: two identical creates, one link in the database, same id both
times.

## DELETE means deactivate


`-on-deactivate delete` is available and prints a warning saying what it costs.
Under it, a person who may act as other users is still only deactivated. The
upstream's intent, that they stop getting in, is met, and so is the removal of
their sessions. The answer is `204`, and the trail records
`scim.privileged_kept`. Removing an administrator's account outright is left to
an administrator of this deployment. Refusing the DELETE instead would leave a
departed administrator signed in.

## Deactivation ends sessions

A deactivated account with a live session is still a signed-in person. Every
path that deactivates — PATCH, DELETE — revokes sessions in the same
transaction.

## Groups

`/Groups` is the half an enterprise actually connects SCIM for. Users would
arrive on first sign-in anyway; **membership would not** — and membership is what
every authorization rule reads.

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
is membership churn — one PATCH per person joining or leaving. And a `remove`
whose dialect the server does not understand, treated as an unsupported path,
returns **200**.

The upstream records the removal as done and never sends it again. The person
keeps the group and everything it grants, permanently, while the upstream's own
console shows them as removed. Nothing anywhere is in a state that looks wrong.

So a member operation that cannot be read is a **400**. A refused PATCH is
retried; a misread one is not.

### The dialects

All of these mean "remove this member", and all were handled:


Two more distinctions that are silent when wrong:

- **`replace` on `members` is not `add`.** It sets the list, so everybody absent
  is removed. Read as an add, a departed employee stays in the group while the
  upstream reports the sync complete.
- **`PUT` with no `members` means no members**, unlike `PATCH`, where an absent
  field means "leave it alone". That is what distinguishes the two verbs, and
  treating them alike makes a group impossible to empty.

### displayName versus the name in a token

`core.groups.name` is constrained to `^[a-zA-Z0-9._-]{1,64}$`, because it travels
through JSON arrays, SAML attribute values and LDAP filters, where a space or a
quote means something else. Upstream display names routinely contain both —
"Engineering Team", "Finance & Legal".


Matching is on `externalId` alone. Matching on `displayName` would make a rename
look like the deletion of one group and the creation of another, revoking
everything the first one granted.

### A source manages only the groups it creates

If a `POST /Groups` derives a name that a group in the organisation already
has, the request is refused with `409 uniqueness`. The existing group might
have been made by an operator, made by another source, or have members who may
impersonate. Each group has at most one source, and a group a source manages
cannot be given impersonation. Both rules are enforced by the database, so they
also hold for any other writer:

- `signari group impersonation -grant` on a group a source manages is refused;
- a source cannot be linked to a group that may impersonate.

The reason is the one directory sync already follows. Whoever administers the
upstream decides who is in its groups. Before this, sending a matching display
name took the existing group over: the upstream's users went in, everyone else
was removed, and the group kept everything it already granted. If you want an
upstream group to reach an application, let the source create the group and
then release the application to it.

### Two deliberate asymmetries with /Users

| | Users | Groups |
|---|---|---|
| `DELETE` | **deactivates** | **deletes** |
| a member/user we do not know | — | **400 with the reason** |

Deleting a person destroys the audit trail of everything they did, which is the
thing you most need about somebody who has just left. A group holds no history of
its own — who was added and when lives in the audit events — and a deprovisioned
group that lingers keeps granting whatever it grants.

A member naming a user this source never provisioned is a 400 rather than a 500,
because an upstream retries a 500 unchanged forever and acts on a 400.

## What is not implemented, and therefore not advertised

| | |
|---|---|
| bulk | `ServiceProviderConfig` says `supported: false` |
| sort, etag, changePassword | same |

Advertising a capability that 404s is the failure this project sweeps for —
which is why `/Groups` entered `/ResourceTypes` only when it was implemented,
and why `ResourceTypes` now counts its own list rather than carrying a number
beside it that can drift.

Filtering supports exactly `userName eq "..."` on `/Users` and
`displayName eq "..."` on `/Groups`, which is what both upstreams
send before every create. Anything else is a **400**, not an ignored parameter:
ignoring an unrecognised filter returns the whole directory, and a caller
reading the first result would then match the wrong person.

## Verified against a running engine


## Three bugs this found, none of them in SCIM

Running it against the real schema found mistakes the compiler cannot see,
because SQL in a string is not type-checked:

- **`display_name` on `core.users` does not exist.** Names live on the link row,
  as `core.directory_links.remote_name` already does — a name is a fact one
  upstream asserts, and two upstreams asserting different names is a conflict
  with no correct resolution.
- **`user_handle` is NOT NULL with no default**, so every insert site must
  generate the 64-byte WebAuthn handle.
- **`status = 'inactive'` is not a valid status.** The constraint allows
  `active | deactivated | locked`. "inactive" is the obvious English word and
  not one of the three.

And the fourth, which was **not** in new code at all:

- **`core.sessions.revocation_reason = 'admin'`** in `internal/directory/apply.go`
  — the constraint requires `admin_revoke`. That statement failed, so the whole
  transaction rolled back, so **the directory sync's deactivation never
  happened**: a departed employee stayed active *and* stayed signed in.

  It passed its tests because none of them gave the user a session, so the
  UPDATE matched zero rows and its values were never checked. The test now
  creates a session before the deactivation, and fails with the old value
  restored.
