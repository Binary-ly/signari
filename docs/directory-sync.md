# Directory sync: Google Workspace, Microsoft Entra ID and LDAP

```sh
signari dir add -org <uuid> -kind google -slug workspace \
  -file service-account.json -domain example.com -impersonate admin@example.com

signari dir add -org <uuid> -kind entra -slug tenant -file entra.json

# LDAP, Active Directory and FreeIPA: see docs/ldap-source.md
signari dir add -org <uuid> -kind ldap -slug corp -ldap-url ldaps://dc01:636 ...

signari dir sync -slug workspace            # preview, writes nothing
signari dir sync -slug workspace -apply
```

The Admin API registers, tunes, maps and syncs sources the same way under
`/admin/organizations/{orgID}/directories`, running the same sync as the
command; see [admin-api.md](admin-api.md).


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

A new remote record whose address matches an existing local account adopts it,
unless that person may act as other users. Such a person is never adopted, and
a linked person who later came to administer is never re-addressed by the
directory. Each skip is recorded as `directory.privileged_skipped`, and the rest
of the run carries on. Deactivation is never skipped, because a departed
administrator must stop getting in.

Somebody a paged fetch returns twice is one person, and the later entry is the
one kept. Two different entries with one address are two people claiming one
account: a source links a person once, so the run stops, names the address and
changes nothing. Fix it upstream and sync again.

A run is one transaction, and writers of addresses and usernames in that
organisation wait for it to commit: 100,000 people are created in about eight
seconds, measured on a laptop, and a later run touches only what changed.

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

## On a schedule

A source can sync itself, so that somebody who left stops signing in without anybody
writing a cron job:

```sh
signari dir set -slug corp -sync-interval 3600    # hourly; 300 to 604800 seconds, 0 stops it
```

`signari serve` looks every minute for what is due and runs `dir sync -apply`, with
every rule that has. The first run is one interval after the setting is made, so
setting it applies nothing at once.

A plan past the ceiling is refused, and with nobody at the terminal to read that, it
goes on the source as its last error, where `dir list` and the Admin API show it, and
into the trail as `directory.scheduled_sync`. A failed sync waits for its next turn
rather than being asked again every minute. A disabled source, one in dry run and
any in a suspended organisation are left alone, so a schedule is safe to set before
a source is trusted. Of several nodes, one takes each source. A sync that runs past
thirty minutes loses its turn.

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
| a user removed upstream | deactivated, sessions ended, each application they reached sent a back-channel logout notice |
| a user still present | untouched |
| empty directory, 50 users local | **refused**, nothing written |
| two leavers out of fifty | allowed |
| a rename | one update, not a delete plus a create |
| suspended or archived upstream | deactivated here |
| a page failing mid-fetch | error, and no partial list returned |
| `mail` empty in Entra | falls back to `userPrincipalName` |

## Groups

A sync reconciles group membership only when the source fetches groups, and
only for groups an operator mapped:

```sh
signari dir set -org <uuid> -slug corp -fetch-groups
signari dir group-map -org <uuid> -slug corp \
  -remote-group 'cn=engineering,ou=groups,dc=example,dc=com' -group engineering
```

| Source | What a group is called | Nesting | Needs |
|---|---|---|---|
| LDAP | its DN, from `memberOf` or `-group-attribute` | Active Directory: resolved for each mapped group with the in-chain matching rule; elsewhere, direct only | read access to the attribute |
| Entra | its object id | transitive (`transitiveMemberOf`) | `GroupMember.Read.All` |
| Google | its address | direct only | `admin.directory.group.readonly` delegated |

The names are chosen so a mapping cannot be claimed from upstream. A display
name is not unique, and anybody able to create a group could give one the name
of a mapped group; an id, an address or a DN cannot be reused that way.

A source that does not fetch groups changes no membership, which is different
from a source saying somebody is in no groups. Removals are bounded by the
same ceiling as deactivations. Fetching is off by default because it needs more
of the upstream than reading users does. Until October 2026 no source fetched a
group at all, so group mappings changed nothing.

## What is not verified

The **LDAP** source has been run against a real OpenLDAP server, over TLS with a
private CA, including a rename across organisational units and a server-side size
limit — see [LDAP as a source](ldap-source.md).

**Neither the Google nor the Entra adapter has been run against real Google or
real Microsoft.** The fakes
match the documented response shapes, which proves pagination, error handling,
credential exchange and the reconciler — but not that the shapes are right.

That needs credentials, and it is the one part I cannot do alone. Until then the
honest claim is: the dangerous half is tested, the compatibility half is not. Run
a dry run first, and read it.
