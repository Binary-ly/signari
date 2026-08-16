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
