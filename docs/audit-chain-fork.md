# The audit chain forked under concurrency

A tamper-evident log is a **line**: each entry hashes its predecessor, so
removing or editing one breaks every entry after it. Two entries claiming the
same predecessor is a fork, and a fork is indistinguishable from a deletion when
the chain is verified.

The chain forked whenever two audit events were written at the same time.

## How it was found

Running two instances against one database, to test high availability. The audit
tests started failing on data nobody had touched:

```
audit_test.go:64: chain reported broken at id 136 on untouched data
```

The data says it plainly:

```
133  admin.user_created     prev=3075cd22  entry=077eeb5e
134  admin.user_created     prev=077eeb5e  entry=c28a4116
135  oauth.code_reused      prev=c28a4116  entry=80ab632b
136  admin.client_updated   prev=c28a4116  entry=34531d0e   ← same predecessor
```

**This was never specific to running two instances.** Two concurrent sign-ins on
a single instance do exactly the same thing. Two instances only made it frequent
enough to notice — which is the argument for testing the deployment shape you
intend to run.

## The guard that did not guard

```go
SELECT entry_hash FROM core.audit_events ORDER BY id DESC LIMIT 1 FOR UPDATE
```

The comment above it said this serialises concurrent appenders. It does not, and
the reason is a property of `READ COMMITTED` that is easy to miss:

```
T1 and T2 both find row 134 as the tail. T1 locks it.
T2 blocks.
T1 inserts 135 (prev = 134) and commits, releasing the lock.
T2 wakes, RE-READS ROW 134 — unchanged, so it proceeds — and inserts 136,
   also claiming 134 as its predecessor.
```

The lock was held on the row the query had already chosen. The `ORDER BY` was
never re-evaluated, so T2 never saw that the tail had moved.

## The fix

A transaction-scoped advisory lock on the **chain**, rather than a row lock on
its current tail:

```go
SELECT pg_advisory_xact_lock($1)   // then read the tail, then insert
```

Correct by construction rather than by an isolation-level subtlety. It is
transaction-scoped, so a commit or rollback releases it and a process that dies
mid-append cannot wedge the log. The key is a constant because the chain is
global — it is verified in id order across every organisation, so a
per-organisation lock would permit exactly the interleaving this prevents.

## Proven both ways

12 concurrent writers, on a fresh database:

```
with the old row lock       2–3 forks
with the advisory lock      none
```

The test walks the whole table for any two entries sharing a predecessor, so it
also catches a fork created by any other path.

## Why this mattered more than it looks

Verification reported tampering where there was none. A log that cries wolf is a
log nobody checks — and this one is the record you reach for when you need to
know what an attacker did.

It also means the chain proved nothing while it was forked: "broken" was the
normal state under load, so a real deletion would have looked like Tuesday.

## Living with a chain that is already broken

A deployment that ran the buggy version can never produce a verified export
again — of any period, including entries written correctly long afterwards. The
log stops being evidence, which is a serious problem for a log kept as evidence.

```sh
signari audit checkpoint -by "you@example.com" \
  -reason "chain forked before the advisory-lock fix; see docs/audit-chain-fork.md"
```

A checkpoint **repairs nothing.** Nothing is rewritten, re-linked or removed,
because rewriting entries to close a break is exactly the operation the chain
exists to make detectable — a tool that did that would be a tool for laundering
a deletion.

It is a *declaration*, recorded in the chain itself, that everything before it
is not asserted and verification restarts here. The export then says so, at
least as loudly as it says "verified":

```
Chain verified over 235 entries SINCE A CHECKPOINT.

The 5465 entries before it are NOT asserted by this export.
A checkpoint was declared on 2026-08-16 by suliman@binary.ly:
  chain forked before the advisory-lock fix; see docs/audit-chain-fork.md

A checkpoint repairs nothing. It records that the earlier chain was
already broken and that verification restarts here.
```

### Why this is not a way to hide a deletion

That is the question to ask of any feature like this, and there are four
answers:

- **It is refused on a sound chain.** On an intact log a checkpoint can only
  narrow what a later verification covers, so there is no legitimate reason to
  declare one.
- **It is itself an audit entry**, written through the ordinary path and linked
  like any other. Declaring one cannot be done without leaving a mark in the
  very chain it starts, and removing that mark breaks the chain at its
  successor.
- **It covers only what precedes it.** A break *after* the checkpoint still
  fails the export. Tested by deleting an entry after one and confirming the
  refusal.
- **The reason is mandatory** and is carried into every export that crosses it,
  so "we upgraded past a known bug" and a blank line are visibly different
  documents.

Only the *link* from the starting entry to its predecessor is disclaimed. The
entry's own hash is still checked, so a checkpoint cannot smuggle an altered
entry in at the boundary — also tested.

Somebody with database access and the will to use it can still destroy evidence.
A hash chain never prevented that; it makes it visible. A checkpoint keeps it
visible while letting the honest case carry on.

### The report has to point at the right break

The first version reported the *old, disclaimed* fork at entry 136 when the
actual problem was a row deleted at 5635. An operator who knew about 136 would
have recognised it and moved on — the worst possible outcome for a report that a
row has gone missing. It now names the break after the checkpoint and says
explicitly that the declaration does not cover it.

## Existing chains cannot be repaired

By design. Rewriting entries to close a fork is exactly the operation the chain
exists to make detectable, so there is no repair tool and there will not be one.
A database that was written to concurrently before this fix has forks in its
history, and `signari export audit` will report them at those points.

The honest position for such a deployment: the chain is trustworthy from the
first entry written after the upgrade, and the forks before it are a known
artefact of this bug rather than evidence of tampering. That is worth recording
somewhere an auditor will see, because "we know why those are there" is not
something to reconstruct later from memory.

## A note on testing this

The tests that prove a break is detected have to *create* one — deleting and
altering audit rows — which breaks that database's chain permanently.

The first version ran them against the shared test database and left it broken
at id 688, failing three unrelated audit tests on data they had not touched.
That is precisely the "cries wolf" outcome this whole area is about, produced by
the tests written to prevent it.

They now require `SIGNARI_DESTRUCTIVE_TEST_DSN` and skip without it:

```sh
createdb signari_scratch
SIGNARI_DSN=…signari_scratch signari migrate all
SIGNARI_DESTRUCTIVE_TEST_DSN=…signari_scratch go test ./internal/audit/
```
