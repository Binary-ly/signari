# Directory sync: Google Workspace and Microsoft Entra ID

```sh
signari dir add -org <uuid> -kind google -slug workspace \
  -file service-account.json -domain example.com -impersonate admin@example.com

signari dir add -org <uuid> -kind entra -slug tenant -file entra.json

signari dir sync -slug workspace            # preview, writes nothing
signari dir sync -slug workspace -apply
```


## Directory sync is where data loss lives

The failure is not subtle and it is not rare. A filter that matches fewer people
than intended, a paginated fetch that stops early, an API returning an empty page
during an outage — every one of those looks *identical* to "everybody left the
company", and a naive reconciler dutifully deactivates them all.

So the defaults are cowardly on purpose:

| | |
|---|---|
| `dry_run` | **true** — a new source writes nothing until told twice |
| `on_missing` | **report** — names who would go, deactivates nobody |
| `max_deactivate_percent` | **20** — above this the whole sync is refused |

Each is turned off deliberately, after somebody has read a dry run.

### Refused, not truncated

A plan that would deactivate more than the ceiling is refused **entirely** — not
applied partially, not trimmed to the first N. The number itself is the evidence
that the input was wrong, and applying any of it would be acting on input we have
just decided not to believe.

```
this sync would deactivate 50 of 50 active users (100%), over the 20% ceiling.
Nothing has been applied. A cliff like this is almost always a bad fetch -- a
filter matching too little, a truncated page, an upstream outage -- rather than
that many people leaving at once.
```

The ceiling is enforced in `Apply` as well as in the caller, because `Apply` is
the function that does the damage and a rule enforced only at the call site is
one a future caller forgets.

Reactivations are **not** counted against it: the ceiling exists to stop mass
removal, and refusing to restore people because too many are being restored would
be the opposite of its purpose.

## Matching is on the remote id, never on email

Somebody changes their surname and their email with it. Matching on email reads
that as a departure plus an arrival: one account deactivated, one created, and
the person locked out of everything they owned. `core.directory_links` is keyed
on the upstream's immutable id, and a remote record without one is skipped rather
than matched by address.

## A short list is never success

Both adapters treat a failure part-way through pagination as an **error**, never
as a shorter list. This is the most dangerous possible bug in the fetch layer:
the reconciler cannot distinguish "these are all the users" from "these are the
ones we read before something broke", so the fetch must not blur it.

- **Google** paginates with `nextPageToken`; a service account also needs
  domain-wide delegation and an administrator to impersonate, which is checked up
  front because Google's 403 explains nothing.
- **Entra** paginates with an absolute `@odata.nextLink` carrying an opaque skip
  token, followed *as given* — rebuilding the query from parts loses the token and
  re-reads page one forever.

Both cap pagination at 500 pages rather than looping without bound.

Google's scope is `admin.directory.user.readonly`. A sync that can write to
somebody's Workspace is a far larger blast radius than this feature needs.

## The churn bug, found by syncing twice

The first version created users correctly and then proposed the **same two
updates on every subsequent run**, forever. `Action` did not carry the display
name, so the link stored the email address as the name, and each run compared
`"Alice"` against `"alice@example.test"` and saw a difference.

Invisible on a first run. The test now syncs twice and asserts the second one
proposes nothing — which is the only way that class of bug shows up.

## Verified

Against the real schema and a faithful fake of each API:

| | |
|---|---|
| create, then re-sync unchanged | second run proposes nothing |
| a user removed upstream | deactivated, sessions revoked |
| a user still present | untouched |
| empty directory, 50 users local | **refused**, nothing written |
| two leavers out of fifty | allowed |
| a rename | one update, not a delete plus a create |
| suspended or archived upstream | deactivated here |
| a page failing mid-fetch | error, and no partial list returned |
| `mail` empty in Entra | falls back to `userPrincipalName` |

## What is not verified

**Neither adapter has been run against real Google or real Microsoft.** The fakes
match the documented response shapes, which proves pagination, error handling,
credential exchange and the reconciler — but not that the shapes are right.

That needs credentials, and it is the one part I cannot do alone. Until then the
honest claim is: the dangerous half is tested, the compatibility half is not. Run
a dry run first, and read it.
