# Directory sync: Google Workspace, Microsoft Entra ID and LDAP

## Introduction

Acme already keeps its people in a company directory, such as Google Workspace,
Microsoft Entra ID or Active Directory. Entering them all again in Signari would
be slow, and the two lists would soon disagree.

A "directory sync" reads people from that directory and makes Signari match it.
It creates the people who joined, updates the people who changed, and
deactivates the people who left. A mistake here can deactivate everybody at
once, so a new source changes nothing until you have read what it would do.

You add a source with `signari dir add`, or through the
[Admin API](admin-api.md). A source can be Google Workspace, Entra, or a
Lightweight Directory Access Protocol ([LDAP](glossary.md#ldap)) directory.

> [!NOTE]
> To read OpenLDAP, Active Directory or FreeIPA, see
> [LDAP as a source](ldap-source.md).

## Add a source and sync it

These commands add a Google Workspace source, an Entra source and an LDAP source,
then preview a sync and apply it:

```sh
signari dir add -org <uuid> -kind google -slug workspace \
  -file service-account.json -domain example.com -impersonate admin@example.com

signari dir add -org <uuid> -kind entra -slug tenant -file entra.json

# LDAP, Active Directory and FreeIPA: see docs/ldap-source.md
signari dir add -org <uuid> -kind ldap -slug corp -ldap-url ldaps://dc01:636 ...

signari dir sync -slug workspace            # preview, writes nothing
signari dir sync -slug workspace -apply
```

In this example, `-impersonate` names the Google administrator the service
account acts as. The `...` on the LDAP line stands for the LDAP settings, which
[LDAP as a source](ldap-source.md) lists.

The Admin API registers, tunes, maps and syncs sources the same way, under
`/admin/organizations/{orgID}/directories`. It runs the same sync as the
command. See [the Admin API](admin-api.md).

## Directory sync is where data loss lives

The failure is not subtle, and it is not rare. A filter can match fewer people
than intended. A paginated fetch can stop early, or an API can return an empty
page during an outage. Every one of those looks *identical* to
"everybody left the company". A naive reconciler dutifully deactivates them all.

So the defaults are cowardly on purpose:

| | |
|---|---|
| `dry_run` | **true** — a new source writes nothing until told twice |
| `on_missing` | **report** — names who would go, deactivates nobody |
| `max_deactivate_percent` | **20** — above this the whole sync is refused |

Each is turned off deliberately, after somebody has read a dry run. A "dry run"
reports what a sync would do, and changes nothing.

### Refused, not truncated

A plan that would deactivate more than the ceiling is refused **entirely**. It is
not applied in part, and not trimmed to the first N. The number itself is the
evidence that the input was wrong. Applying any of it would be acting on input
we have already decided not to believe.

This is the message a refused sync prints:

```
this sync would deactivate 50 of 50 active users (100%), over the 20% ceiling.
Nothing has been applied. A cliff like this is almost always a bad fetch -- a
filter matching too little, a truncated page, an upstream outage -- rather than
that many people leaving at once.
```

The ceiling is enforced in `Apply` as well as in the caller. `Apply` is the
function that does the damage, and a rule enforced only at the call site is one
a future caller forgets.

Reactivations are **not** counted against it. The ceiling exists to stop mass
removal. Refusing to restore people because too many are being restored would
be the opposite of its purpose.

## Matching is on the remote id, never on email

Suppose Ada changes her surname, and her email address with it. Matching on
email reads that as a departure plus an arrival: one account deactivated, one
created, and the person locked out of everything they owned.

`core.directory_links` is keyed on the upstream's immutable ID. A remote record
without one is skipped, rather than matched by address.

A new remote record whose address matches an existing local account adopts it,
which links the record to that account instead of creating another. The
exception is a person who may act as other people through
[impersonation](impersonation.md). Such a person is never adopted, and a linked
person who later came to administer is never re-addressed by the directory.

Each skip is recorded as `directory.privileged_skipped`, and the rest of the run
carries on. Deactivation is never skipped, because a departed administrator must
stop getting in.

Somebody a paged fetch returns twice is one person, and the later entry is the
one kept. Two different entries with one address are two people claiming one
account. A source links a person once, so the run stops, names the address and
changes nothing. Fix it upstream and sync again.

A run is one transaction. Anything else writing addresses or usernames in that
organisation waits for it to commit. Creating 100,000 people takes about eight
seconds, measured on a laptop, and a later run touches only what changed.

## A short list is never success

The Google and Entra adapters both treat a failure part-way through pagination
as an **error**, never as a shorter list. This is the most dangerous possible
bug in the fetch layer. The reconciler cannot tell "these are all the people"
from "these are the ones we read before something broke". So the fetch must not
blur it.

- **Google** paginates with `nextPageToken`. A service account also needs
  domain-wide delegation and an administrator to impersonate. That is checked up
  front, because Google's 403 explains nothing.
- **Entra** paginates with an absolute `@odata.nextLink` carrying an opaque skip
  token, followed *as given*. Rebuilding the query from parts loses the token,
  and re-reads page one forever.

Both cap pagination at 500 pages rather than looping without bound.

Google's scope is `admin.directory.user.readonly`. A sync that can write to
somebody's Workspace is a far larger blast radius than this feature needs.

## On a schedule

A source can sync itself, so that somebody who left stops signing in without
anybody writing a cron job:

```sh
signari dir set -slug corp -sync-interval 3600    # hourly; 300 to 604800 seconds, 0 stops it
```

`signari serve` looks every minute for what is due, and runs `dir sync -apply`
with every rule that has. The first run is one interval after the setting is
made, so setting it applies nothing at once.

A plan past the ceiling is refused. Nobody is at the terminal to read that, so
the refusal goes on the source as its last error. `dir list` and the Admin API
show it there. It also goes into the audit trail as `directory.scheduled_sync`.

A failed sync waits for its next turn, rather than being asked again every
minute. A disabled source, one in dry run, and any in a suspended organisation
are left alone. So a schedule is safe to set before a source is trusted.

When Signari runs on several nodes, one node takes each source. A sync that runs
past thirty minutes loses its turn.

## The churn bug, found by syncing twice

The first version created people correctly, and then proposed the **same two
updates on every subsequent run**, forever. `Action` did not carry the display
name, so the link stored the email address as the name. Each run compared
`"Alice"` against `"alice@example.test"`, and saw a difference.

The bug was invisible on a first run. The test now syncs twice, and asserts that
the second sync proposes nothing. That is the only way this class of bug shows
up.

## Verified

These were checked against the real schema and a faithful fake of each API:

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

A sync reconciles group membership only when the source fetches groups, and only
for groups an administrator mapped. These commands turn on fetching groups, and
map a remote group to a [group](groups.md) in Signari:

```sh
signari dir set -org <uuid> -slug corp -fetch-groups
signari dir group-map -org <uuid> -slug corp \
  -remote-group 'cn=engineering,ou=groups,dc=example,dc=com' -group engineering
```

Each kind of source names a group its own way. An LDAP group is named by its
distinguished name (DN), its full name in the directory:

| Source | What a group is called | Nesting | Needs |
|---|---|---|---|
| LDAP | its DN, from `memberOf` or `-group-attribute` | Active Directory: resolved for each mapped group with the in-chain matching rule; elsewhere, direct only | read access to the attribute |
| Entra | its object id | transitive (`transitiveMemberOf`) | `GroupMember.Read.All` |
| Google | its address | direct only | `admin.directory.group.readonly` delegated |

The names are chosen so that a mapping cannot be claimed from upstream. A display
name is not unique, and anybody able to create a group could give one the name
of a mapped group. An ID, an address or a DN cannot be reused that way.

A source that does not fetch groups changes no membership. That is different
from a source saying somebody is in no groups. Removals are bounded by the same
ceiling as deactivations.

Fetching is off by default, because it needs more of the upstream than reading
people does. Until October 2026 no source fetched a group at all, so group
mappings changed nothing.

## What is not verified

The **LDAP** source has been run against a real OpenLDAP server, over Transport
Layer Security ([TLS](glossary.md#tls)) with a private certificate authority
(CA). That run included a rename across organisational units and a server-side
size limit. See [LDAP as a source](ldap-source.md).

**Neither the Google nor the Entra adapter has been run against real Google or
real Microsoft.** The fakes match the documented response shapes. That proves
pagination, error handling, credential exchange and the reconciler, but not that
the shapes are right.

That needs credentials, and it is the one part that cannot be done alone. Until
then, the honest claim is this: the dangerous half is tested, and the
compatibility half is not. Run a dry run first, and read it.
