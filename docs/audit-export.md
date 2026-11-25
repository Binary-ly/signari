# Audit export

## Introduction

A compliance reviewer, or anyone looking into an incident, often needs Signari's
audit trail as a file. The hard part is showing that the file is the whole trail,
and that nobody edited it.

`signari export audit` writes the trail as comma-separated values (CSV), with the
hash chain that proves it is complete. `signari audit archive` moves the oldest
entries out of the database into such a file, without breaking the chain.

Both are commands you run from the command line.

## Export the trail

Export the whole trail to a file, or one organisation's entries for a range of
dates:

```sh
signari export audit -out audit.csv
signari export audit -org <uuid> -from 2026-01-01 -until 2026-02-01
```

## Any system can produce a CSV

The question a compliance reviewer cannot normally answer is whether the export is
**complete and unedited**. A CSV is a text file. One row removed between the
database and the reviewer looks exactly like a row that never existed.

This trail is hash-chained: each entry commits to its predecessor. So the export
carries the chain with it:

- The chain is **verified before any rows are written**.
- The verification and the rows are read from **one snapshot**, so a row written
  while the export runs is in neither.
- `entry_hash` is a column, not a footnote.
- The summary states the first and last hash of the range.

Until October 2026 they were two snapshots. Six administrator commands were
run in a loop, writing to the trail during the exports. Seven runs in eight then
wrote more rows than the verification had read. Each wrote up to three more, under "Chain verified over
all" entries.

Together, those let a reviewer confirm that the file they hold is the trail the
database has. A later dispute can then be settled by recomputation, instead of
trust.

At the end of an export, the summary looks like this:

```
  348 rows
  first entry hash : de712256df9e28bf0015e80ab0b208cf…
  last entry hash  : 974b5f06389b672ab64bba7275ae864d…

  Chain verified over all 348 entries.
```

The summary goes to **stderr**. So redirecting stdout to a file still shows the
administrator what they produced. It also means an integrity statement can never be
mistaken for a row of data.

A failed verification is stated loudly, and exits non-zero. An export that quietly
omitted it would carry the appearance of integrity without the fact. That is worse
than no export at all.

## Pseudonymous by construction

The trail stores `subject_id`, never an email address, and never an IP address
treated as identity. So an export says what happened to which account. Resolving an
account to a person is a separate, deliberate step somebody has to take.

## The bug this feature found on its first run

This section is the record of a defect the first export found, and of how it was
fixed.

The very first export reported **the chain broken at entry 371**, and the audit
tests had passed minutes earlier. It was real.

`core.audit_events` had two foreign keys with `ON DELETE SET NULL`:

```
org_id          -> core.organizations
admin_token_id  -> core.admin_tokens
```

Both of those columns are **inside the chain hash**. So deleting an organisation,
or revoking and deleting an admin token, silently rewrote historical audit rows.
Every rewritten row then failed verification.

Demonstrated rather than assumed, before and after the fix:

```
insert an audit row attributed to a token
delete the token
  before fix:  attributed  t -> f      (history rewritten underneath it)
  after fix:   attributed  t -> t
```

### Why this mattered more than it sounds

The point of a hash-chained trail is that deletion and alteration are
**detectable**. A chain that reports "tampered" after an ordinary administrative
action is a smoke alarm that goes off when somebody makes toast. Within a month
nobody looks at it, and the real signal is lost along with the false ones.

Revoking admin tokens is routine. This would have fired constantly.

### The fix

Migration 0043 drops both constraints. The columns keep their values.

An audit row is not current state. It records what was true at the time. An entry
naming an organisation or token that no longer exists is not dangling: it is the
point. Referential integrity is a rule for current state.

`TestRevokingATokenDoesNotRewriteHistory` asserts that the referential actions stay
gone, because the natural "tidying" fix is to add them back.

### The damage was not repairable

A hash chain cannot be re-sealed: rehashing the affected rows would defeat the
mechanism. The development database's trail was truncated, and a fresh chain
started. That is exactly the decision a production deployment would face, and the
argument for this landing before release rather than after.

If it ever happens in production, the honest response is the same: start a new
chain, and record why, in the trail itself.

## Archiving the oldest entries

The trail grows for as long as the deployment runs. To move the oldest part out of
the database without losing the chain:

```sh
signari audit archive -until 2026-01-01 -out audit-to-2026-01-01.csv -by "ops on-call"
signari audit verify -file audit-to-2026-01-01.csv     # anywhere, no database
```

The command verifies the whole chain first, and refuses if it does not verify.
Removing part of a broken chain would remove the evidence of the break.

A chain that verifies only from a [checkpoint](audit-chain-fork.md) cannot be
archived either. The part before the checkpoint is disclaimed, and a file cannot
make it verify.

It archives a prefix of the chain: every entry before the first one dated on or
after `-until`. The file carries every column the hash covers, including each
entry's link to the one before and its hash version. So `audit verify -file` checks
it with nothing but the file.

The file is created new, and never written over an existing one. It is readable by
its owner alone, and synced to disk before anything is removed.

Then, in one transaction, the command records an `audit.archived` entry in the chain
and removes the archived entries. The entry names the last archived hash, how many
entries were archived, and the file's SHA-256.

From then on, verification starts from that hash, so the first entry left must still
link to the last one archived. Removing one more entry breaks the chain exactly as
before. The command refuses if the chain no longer starts where the file ends. It
also refuses if the entries it would remove are not exactly the ones it wrote.

Each archive record is archived in turn by the next archive, inside its file. So a
sequence of archive files chains: each one starts from the last hash of the file
before. `audit verify -file` prints the earlier file's SHA-256 when the file holds
its record.

> [!WARNING]
> Once archived, a file is the only copy of those entries. Keep it as you keep
> backups.
