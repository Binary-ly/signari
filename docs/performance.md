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

## A million people

The same laptop, busy with other work, the database on it over loopback: 1,000,000 people in
1,000 organisations, 1,000,000 sessions and 5,000,000 audit events, 2.6 GB, against a database
of one person in the same 1,000 organisations, measured before the fixes below. Four workers,
median of two runs, milliseconds.

```
                     one person             1,000,000 people
                     p50      p99           p50      p99
discovery            0.36     1.05          0.38     1.68
client credentials   1.20     3.61          1.33     5.88
introspection        1.41     4.31          1.66     6.88
sign-in              44.5     97.2          46.9     96.7
refresh              4.56     20.2          3.05     11.3
userinfo             1.50     6.52          1.12     5.45
```

The size of the directory does not show in these. That is the result, and what it took to be
able to say so is below. Everything was found by counting the rows read by sequential scan
during the run, rather than by the clock:

- **On every sign-in.** An organisation's budgets were read through the text of its key, which
  no index serves, and the instance's first organisation was read and sorted twice. Neither
  shows at one organisation, and both grow with the number of tenants.
- **On every janitor pass.** Retention read every session, and the audit head read the trail,
  3.4 s at five million events, every minute for the life of the deployment.

The second list was longer than the seed could show. Five more sweeps had no index, on tables
that were only cheap because nothing had been put in them. So the tests now run a real pass and
a real sign-in past the planner and ask of each statement whether any index could serve it,
rather than keeping a list of statements somebody remembered.

This is one node on one machine, so read it for the shape. What a network between the engine and
its database does to a sign-in, which makes many round trips, is not in these numbers.

## A hundred thousand people

One client over loopback on the same laptop, busy with other work at the time, against one
organisation of 100,000 people, each linked to a SCIM source, and 100,000 relations.

```
SCIM, 100 people a page     first page   p50  9 ms   p99 40 ms
                            middle       p50 15 ms   p99 66 ms
                            last page    p50 21 ms   p99 64 ms
AuthZEN, 100 evaluations    one request  p50  2 ms   p99 7-11 ms, five statements
```

The evaluations were 17 ms until this was measured. A batch named its subject once per
question and the join found their relations once per mention, so a hundred questions cost
twelve times what ten did, on the same five statements. Counting statements, which a test
does, could not see it. The lists are made distinct now.

Getting to a hundred thousand people found more than the measurements did, because it took
over half an hour and was not finished. Bringing people in took time that grew with the square
of how many, and only on a deployment that had never held any:

| | before | after |
|---|---|---|
| one statement, 20,000 people, new deployment | 103 s | 1.3 s |
| the same, into an organisation of 100 | 243 s | 1.1 s |
| a realm import of 16,000 people, new deployment | 267 s | 17 s |

Three causes, each hidden from a test by a database that already had statistics in it. The
check that an address is nobody's username made one plan for the whole statement, on a table
with nothing to go on, and the plan read the organisation for every row. An import's own
lookups did the same for the length of its transaction. And the CLI's version bump updated one
row for every statement, which a transaction cannot prune behind itself, so each update walked
past all the ones before it. A first directory sync is one such statement, and an import is
what a migration begins with, so a new deployment was the worst place for this to be slow.

## Reproducing

The harness is [`tools/bench`](../tools/bench/README.md): full flows, latency
percentiles, and load shed counted separately from failures. That distinction
matters: a 429 is the server working, and counting it as a failure hides whether
anything is actually broken. Until October 2026 the harness was a file in a session
scratchpad that nobody else could run.

## What this is not

A benchmark. It is one laptop, one instance, one database, no TLS, and a
password chosen to be found in the cache. Treat it as a floor and a shape — the
shape being that sign-in costs Argon2 and everything else is cheap — rather than
a number to put on a page.
