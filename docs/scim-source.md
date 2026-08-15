


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

## Retries are free


Verified live: two identical creates, one link in the database, same id both
times.

## DELETE means deactivate


`-on-deactivate delete` is available and prints a warning saying what it costs.

## Deactivation ends sessions

A deactivated account with a live session is still a signed-in person. Every
path that deactivates — PATCH, DELETE — revokes sessions in the same
transaction.

## What is not implemented, and therefore not advertised

| | |
|---|---|
| `/Groups` | absent from the code **and** from `/ResourceTypes` |
| bulk | `ServiceProviderConfig` says `supported: false` |
| sort, etag, changePassword | same |

An upstream that reads Groups in `/ResourceTypes` will attempt group sync and
report failures the operator cannot fix. Advertising a capability that 404s is
the failure this project sweeps for.

Filtering supports exactly `userName eq "..."`, which is what both upstreams
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
