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
its database does to a sign-in, which makes many round trips, is not in these numbers. The next
section is.

## Three nodes, a million people, the database across the network

Measured in November 2026 on two rented Linux machines in one data centre, AMD EPYC 9655P, 16
threads and 32 GB each. One held PostgreSQL 17 alone, which the engines reached over TLS with a
scram-sha-256 password. A `SELECT 1` on one connection took 0.121 ms at the median and 0.126 ms
at p99. Over the day the median moved between 0.05 and 0.12 ms, so this is a LAN in one data
centre and not a database in another region. The other machine ran three engine processes, each
on two physical cores of its own, behind nginx dealing requests round-robin on loopback, with
the load driver on the remaining two cores. The data was 1,001 organisations, 1,000,000 people,
1,000,000 sessions and 10,000,000 audit events, 5.1 GB.

Sixteen workers, a 10-second warm-up, then five rounds of 15 seconds of each operation. The
table gives the mean of the rounds with its 95% interval, and the p99 is the mean of the rounds'
p99. No round had an error or a 429, and no node logged an error.

```
                         ops/s              p50 ms    p99 ms
discovery                27,433 ± 1,077      0.45      2.37
client credentials       21,415 ±   274      0.66      1.86
introspection            17,574 ±   974      0.89      1.85
sign-in                     274 ±     6     54.65    121.43
refresh                   9,867 ±   144      1.54      3.19
userinfo                 19,359 ± 2,175      0.63      2.20
```

A sign-in crosses the nodes: the authorization request, the password, the consent and the code
each reach whichever node the balancer picks, and every one finished. It is Argon2id that sets
its price, as on one machine.

Two settings were changed for the run, and each refusal that led to them was the engine doing
what it should:

- **Sign-in took turns through 1,000 people.** With sixteen workers signing one person in
  together, every refusal in the audit trail was `{"reason": "throttled"}`: each attempt is
  charged to the account before the password is checked, so sixteen at once look like guessing.
  `bench run -signin-people` makes each sign-in somebody else.
- **The organisation's budgets were raised** to their maximum, 1,000,000 tokens and 1,000,000
  sign-ins a minute, with `signari instance org-budgets`. At the defaults, 6,000 tokens and
  1,200 sign-ins, the warm-up alone spent the sign-in budget and the next sign-in was a 429.

PostgreSQL's data was on tmpfs. The machines' own disk stalled commits for up to 1.5 seconds at a
time (`pg_test_fsync` measured 2 synced writes a second at worst), and every token-issuing worker
stopped together while discovery, which writes nothing, did not. With the data in memory a commit
still runs PostgreSQL's own path, `fsync` and `synchronous_commit` on, at no cost. A deployment's
disk adds its own flush time to everything that writes.

The driver had two cores, so the cheapest operations may be held by the driver rather than the
nodes. The one-machine table above compares one person with a million. This one is a different
shape, and it is not a before-and-after.

The run is [`tools/bench/scale`](../tools/bench/scale/README.md): `database.sh` and `seed.sql` on
the database's machine, `nodes.sh` on the nodes'. Run again from those scripts on a second, fresh
pair of machines, every operation came within the first run's interval: client credentials
20,673 ± 891 a second, sign-in 281 ± 3, refresh 9,809 ± 216, still with no errors.

## A hundred thousand people

One client over loopback on the same laptop, busy with other work at the time, against one
organisation of 100,000 people, each linked to a SCIM source, and 100,000 relations.

```
SCIM, 100 people a page     first page   p50  9 ms   p99 40 ms
                            middle       p50 15 ms   p99 66 ms
                            last page    p50 21 ms   p99 64 ms
AuthZEN, 100 evaluations    one request  p50  2 ms   p99 7-11 ms, five statements
```

The same measurements again in November 2026 on a rented Linux machine (AMD EPYC 9655P), the
engine and PostgreSQL sharing four physical cores and the client on four others, against one
organisation of 100,000 people. Each page shows the median p50 and the worst p99 of three runs of
200 requests. The LDAP line is five rounds of 15 seconds:

```
SCIM, 100 people a page     first page   p50  5.6 ms   p99  8.8 ms
                            middle       p50  7.5 ms   p99 12.5 ms
                            last page    p50  9.8 ms   p99 14.6 ms
SCIM, a group PUT replacing all 10,000 members              0.23 s
LDAP, one person found among 100,000, 16 clients      p50 0.79 ms   p99 2.30 ms   18,307 a second
```

Every page costs two walks of the whole source: the count `totalResults` requires (RFC 7644
§3.4.2), and the offset to the page, an index-only scan. On a table loaded seconds before, with
no vacuum yet, the same last page was p50 22 ms and p99 27 ms, because every row the two walks
pass was still read from the table to see whether it was visible. Autovacuum fixed that within a
minute, and the figures above are from after it.

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

## A page of the Admin API

The same laptop, four workers over loopback TLS, one organisation of 100,000 people, a page of
100 at a time, and the per-token limit raised out of the way. Several runs of each, code before
and after, on the same setup.

| | before | after |
|---|---|---|
| pages a second | 4-18 | 2,070-2,970 |
| p50 | 236-795 ms | 1.3-1.6 ms |
| p99 | 444-2,356 ms | 3-7 ms |
| buffers read for a page | 2,703 | 104 |
| buffers for a page halfway through | 2,619 | 105 |

Every page read all 100,000 people and sorted them, for one row or a hundred. `SELECT id::text
... ORDER BY id` orders by what the select list calls `id`, which is the text, and no index
holds that. And `id::text > $1` is not a seek, so a later page walked from the start. Neither
shows on a table a test can fill, and the first run of the load driver found both. The people,
group, group member, invitation and client lists all page by the key now, and a test runs every
read the Admin API has past the planner.

By default a token gets 50 requests a second (`SIGNARI_ADMIN_TOKEN_RATE`), so that is what a
deployment will see, and it is now the limit and not the database.

That test found three more that a page never showed. A deployment-wide read of the audit trail
sorted the whole trail, because nothing led with its time, the list of event subscriptions
counted its way through every delivery once for each subscription, and a Duo integration
counted its enrolments through the whole table. All three have indexes now.

Two things went wrong measuring this, and they are the reason for "the same setup". The first
runs of the fixed code answered 44 a second: nothing had analysed the table since it was filled,
so the planner took 100,000 rows for a handful. A real table has statistics by then and a load
test run straight after a bulk load does not, so analyse first. And a batch of three runs read a
quarter of the others, for no reason we found, which is why two builds are measured in turn and
more than once before anything is believed. Recording a token's use on every request looked
like the cause of the 44. It was not: with it and without it, in turn, the runs overlap, and it
stayed as it was.

## Everything else a deployment does

None of this had ever been measured. The same machine, 100,000 people, against the engine and
a real upstream built into the load driver: an OpenID provider, a SCIM server and a directory.
Two or three runs of each with no errors, but for the two long runs at the end.

```
Revocation, a token issued and revoked   496-550 pairs/s    p50  7-8 ms    p99 16-19 ms
A person's access token exchanged        338-958/s          p50  3-11 ms   p99 17-37 ms
A pushed authorization request           919-1,932/s        p50  1-2 ms    p99  2-6 ms
A device sign-in started                 719-1,627/s        p50  1-2 ms    p99  4-15 ms
A poll of a device nobody has approved   1,977-2,057/s      p50  2 ms      p99  5-6 ms
An approval asked for over CIBA          1,394-1,428/s      p50  3 ms      p99  7-8 ms
An assertion traded for a token          906-910/s          p50  2 ms      p99  5 ms
A sign-in with a passkey, begin to end   452-462/s          p50  4 ms      p99  9-15 ms
A sign-in through an upstream provider   119-123/s          p50 16 ms      p99 28-32 ms
A TOTP code spent                                           p50  4 ms      p99 10-13 ms
A sign-out                                                  p50  4 ms      p99 13-16 ms

100,000 people pushed out over SCIM      37-39 s, then 262 ms with nothing to do
100,000 people read in from a directory  11.8 s, then 2.1 s with nothing to do, one run
```

The two lines with no rate are the one request of a sign-in, with the password hash before it
kept out of the time. A pushed request and a device start are paced at 6,000 a minute per client,
which is 100 a second through one application, so those lines are short windows under that and
not rates to sustain.

Measuring these found three things that were wrong, which is more than the numbers did.

**A sign-in through a provider that began at an application ended at a 404.** After the person
had signed in upstream, the engine sent them to `/authorize`, and it serves `/oauth2/authorize`.
Every earlier check of a provider stopped at the session, and the test beside the code had the
same wrong path written out, so it passed. It took a driver that insists on a redeemed code at
the end. The router now vouches for every path written down for a browser.

**Starting a device sign-in had no limit.** It answered 3,000 a second, each one a row that
lives ten minutes, from a client that authenticates nothing when it is public. A pushed request
had been fixed for exactly that and this had not. It is paced the same way now.

**A SCIM sync with nothing to do took 325 seconds.** Eight times what creating everybody had
just taken, because the links it had written had not been counted yet, and the planner took
100,000 rows for a handful and walked all of them per person. A sync that writes many links
counts them now, and the same run takes 262 milliseconds.

## Round trips on the token paths, November 2026

The token endpoint, introspection and revocation spent more of their time waiting on the
database than computing. Every decision a request needs is still read on that request: whether
the client is enabled and its organisation in service, whether the token or its session has been
revoked, whether the caller has spent its guesses. What changed is how many round trips that
takes. The client and its two failure counters are read in one. Introspection asks the token's
standing in that same round trip, the token verified first against the keys in memory, so that
nothing is read on behalf of a caller that has not authenticated. Tokens that arrive while their
organisation's budget is being charged are charged together by the next statement, each
answered from its own place in the count, so the limit is exactly what it was. A client revoking
its own access token is one statement, with the audit record written apart so that a record
that cannot be written never undoes a revocation.

Four physical cores were shared by the engine and PostgreSQL (data on tmpfs, `fsync` on), and
the driver ran on four others. Sixteen workers, the old build and the new taking turns in
15-second windows, five turns each, mean and 95% interval:

```
                                before            after
client credentials              3,701 ± 103       5,274 ± 258     +42%
introspection                   2,250 ±  40       2,777 ± 106     +23%
a token issued and revoked      1,165 ± 113       1,465 ± 227     +26%
```

The same night two more cuts were measured on the same machine. A device that is waiting for a
person to approve it is now answered in one statement a poll, where each poll was a transaction
of four round trips: 2,897 polls a second became 3,764 (+30%), three turns of five rounds each,
the two builds taking turns on one database. A sign-in through an upstream provider had been opening a new connection to the provider
for every sign-in and leaving it open. It now uses the same connections throughout, and goes
from 228 a second, with 6,142 sign-ins failed for want of a port, to 292 with none.

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
