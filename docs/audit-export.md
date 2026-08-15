# Audit export

```sh
signari export audit -out audit.csv
signari export audit -org <uuid> -from 2026-01-01 -until 2026-02-01
```


## Any system can produce a CSV

The question a compliance reviewer cannot normally answer is whether the export
is **complete and unedited**. A CSV is a text file. One row removed between the
database and the reviewer looks exactly like a row that never existed.

This trail is hash-chained — each entry commits to its predecessor — so the
export carries the chain with it:

- the chain is **verified before any rows are written**
- `entry_hash` is a column, not a footnote
- the summary states the first and last hash of the range

Together those let a reviewer confirm the file they hold is the trail the
database has, and let a later dispute be settled by recomputation instead of
trust.

```
  348 rows
  first entry hash : de712256df9e28bf0015e80ab0b208cf…
  last entry hash  : 974b5f06389b672ab64bba7275ae864d…

  Chain verified over all 348 entries.
```

The summary goes to **stderr**, so redirecting stdout to a file still shows the
operator what they produced — and so an integrity statement can never be mistaken
for a row of data.

A failed verification is stated loudly and exits non-zero. An export that quietly
omitted it would carry the appearance of integrity without the fact, which is
worse than no export at all.

## Pseudonymous by construction

The trail stores `subject_id`, never an email address and never an IP treated as
identity. So an export says what happened to which account, and resolving an
account to a human is a separate, deliberate step somebody has to take.

## The bug this feature found on its first run

The very first export reported **the chain broken at entry 371**, and the audit
tests had passed minutes earlier. It was real.

`core.audit_events` had two foreign keys with `ON DELETE SET NULL`:

```
org_id          -> core.organizations
admin_token_id  -> core.admin_tokens
```

Both of those columns are **inside the chain hash**. So deleting an organisation,
or revoking and deleting an admin token, silently rewrote historical audit rows —
and every rewritten row then failed verification.

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
action is a smoke alarm that goes off when somebody makes toast: within a month
nobody looks at it, and the real signal is lost along with the false ones.

Revoking admin tokens is routine. This would have fired constantly.

### The fix

Migration 0043 drops both constraints. The columns keep their values.

An audit row is not current state — it records what was true at the time, and an
entry naming an organisation or token that no longer exists is not dangling, it
is the point. Referential integrity is a rule for current state.
`TestRevokingATokenDoesNotRewriteHistory` asserts the referential actions stay
gone, because the natural "tidying" fix is to add them back.

### The damage was not repairable

A hash chain cannot be re-sealed: rehashing the affected rows would defeat the
mechanism. The development database's trail was truncated and a fresh chain
started, which is exactly the decision a production deployment would face — and
the argument for this landing before release rather than after.

If it ever happens in production, the honest response is the same: start a new
chain and record why, in the trail itself.
