# What one instance does under load

Measured, not estimated. `signari` had never been run under sustained load
before this, which for a project that has found most of its bugs by running
things was an obvious gap.

## The numbers

One instance, one PostgreSQL, an 8-core laptop with 16 GB of RAM. Six concurrent
workers driving **complete authorization-code flows**: authorize → sign-in →
resume → token exchange, each with its own cookie jar and PKCE verifier.

```
duration        1m0s with 6 workers
completed       3099 flows (51.6/s)
failed          0
shed for load   2123 (server refused with 429; working as intended)

sign-in         p50 37ms   p95 53ms   p99 95ms
token exchange  p50 1ms    p95 3ms    p99 8ms
```

**51 complete sign-ins per second, zero failures.** Read the two latencies
together: sign-in is dominated by Argon2, which is expensive on purpose. The
token exchange — the operation a busy relying party actually repeats — is a
millisecond.

The 2,123 shed responses are the global bucket refusing excess rather than
queueing it, which is the correct answer to more load than a box can serve.

## What it left behind

More interesting than the throughput.

```
audit chain     0 new forks across ~3,100 concurrent writes
codes           0 unconsumed
connections     8
```

The audit chain is the one worth dwelling on. It **forked whenever two events
were written at once** until the advisory lock went in — see
[the audit chain fork](audit-chain-fork.md). This soak is the first evidence the
fix holds at scale: the only forks in that database are the two at rows 135/136
and 279/280 that predate it, and nothing above row 2,531 forked at all.

On a database created after the fix, the export verifies:

```
Chain verified over all 279 entries.
```

On the older one it refuses, correctly and permanently:

```
WARNING: the audit chain is BROKEN at entry 136 (after checking 92).
signari: the audit chain did not verify
```

That is the honest cost of a chain: a deployment that hit the bug can never
produce a verified export of that history again. There is no repair tool,
because rewriting entries to close a fork is precisely the operation the chain
exists to make detectable.

## Two rate-limiting mistakes the soak found

Both mine, both from the previous day's work, and neither would have shown up in
a test.

### Charging every attempt, not every failure

The per-address limit was 20 attempts per five minutes. The first soak run:
**33,615 refusals and not one completed sign-in.**

A load test from one address is indistinguishable from an attack — but so is
**an office**. Two hundred people behind one NAT gateway signing in at nine
o'clock is completely ordinary, and that limit refuses most of them.

The fix is to charge **failures**, not attempts. A correct password costs
nothing, so the office is unaffected however large it is, while an address
working through a password list is bounded exactly as tightly as before.

### Then a ceiling that duplicated an existing control

The first correction added a generous per-address ceiling on all attempts, to
protect CPU. The next soak completed exactly 600 flows — precisely that ceiling.

It was the wrong control in the wrong place. Flood protection already existed as
a global bucket, and *no* value of a per-address ceiling is right for a large
office behind one gateway. Removed. What remains:

| | |
|---|---|
| global bucket, in process | flood and CPU protection |
| failures per address | one source guessing at many accounts |
| failures per account | many sources guessing at one account |

## Reproducing

The harness is `scratchpad/soak` — full flows, latency percentiles, failures by
kind, and load shed counted separately from failures. That distinction matters:
a 429 is the server working, and counting it as a failure hides whether anything
is actually broken.

## What this is not

A benchmark. It is one laptop, one instance, one database, no TLS, and a
password chosen to be found in the cache. Treat it as a floor and a shape — the
shape being that sign-in costs Argon2 and everything else is cheap — rather than
a number to put on a page.
