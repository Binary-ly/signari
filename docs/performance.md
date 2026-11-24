# What one instance does under load

## Introduction

Before you depend on Signari, you want to know how much one server can do, and
what changes as the number of people grows. This page answers that with
measurements, not estimates.

`signari` had never been run under sustained load before this. For a project that
has found most of its bugs by running things, that was a real gap. Each run below
also found something wrong, and the page says what.

> [!NOTE]
> These numbers are a floor and a shape, not a benchmark. Read [what this is
> not](#what-this-is-not) before you quote one, and [reproducing](#reproducing) to
> run them yourself.

## The numbers

The first run used one instance and one PostgreSQL, on an 8-core laptop with
16 GB of RAM. Six concurrent workers drove **complete authorization-code flows**:
authorize → sign-in → resume → token exchange. Each worker had its own cookie jar
and Proof Key for Code Exchange ([PKCE](glossary.md#pkce)) verifier.

In the results, p50 is the median time. p99 is the time that 99 requests in 100
finished within:

```
duration        1m0s with 6 workers
completed       3099 flows (51.6/s)
failed          0
shed for load   2123 (server refused with 429; working as intended)

sign-in         p50 37ms   p95 53ms   p99 95ms
token exchange  p50 1ms    p95 3ms    p99 8ms
```

**51 complete sign-ins per second, zero failures.** Read the two latencies
together. Sign-in is dominated by Argon2, the password hash, which is expensive on
purpose. The token exchange, the operation a busy application actually repeats,
is a millisecond.

The 2,123 shed responses are the global bucket refusing excess, rather than
queueing it. That is the correct answer to more load than a box can serve.

## What it left behind

What the run left behind is more interesting than the throughput:

```
audit chain     0 new forks across ~3,100 concurrent writes
codes           0 unconsumed
connections     8
```

The audit chain is the one worth dwelling on. It **forked whenever two events
were written at once**, until the advisory lock went in. See [the audit chain
fork](audit-chain-fork.md).

This "soak", a long run under steady load, is the first evidence the fix holds at
scale. The only forks in that database are the two at rows 135/136 and 279/280
that predate it. Nothing above row 2,531 forked at all.

On a database created after the fix, the export verifies:

```
Chain verified over all 279 entries.
```

On the older one it refuses, correctly and permanently:

```
WARNING: the audit chain is BROKEN at entry 136 (after checking 92).
signari: the audit chain did not verify
```

That is the honest cost of a chain. A deployment that hit the bug can never
produce a verified export of that history again. There is no repair tool, because
rewriting entries to close a fork is precisely the operation the chain exists to
make detectable.

## Two rate-limiting mistakes the soak found

Both came from the previous day's work, and neither would have shown up in a
test.

### Charging every attempt, not every failure

The per-address limit was 20 attempts per five minutes. The first soak run ended
with **33,615 refusals and not one completed sign-in.**

A load test from one address is indistinguishable from an attack. But so is **an
office**. Two hundred people signing in at nine o'clock behind one network address
translation (NAT) gateway is completely ordinary. That limit refuses most of them.

The fix is to charge **failures**, not attempts. A correct password costs nothing,
so the office is unaffected however large it is. An address working through a
password list is bounded exactly as tightly as before.

### Then a ceiling that duplicated an existing control

The first correction added a generous per-address ceiling on all attempts, to
protect CPU. The next soak completed exactly 600 flows, precisely that ceiling.

It was the wrong control in the wrong place. Flood protection already existed as
a global bucket. And *no* value of a per-address ceiling is right for a large
office behind one gateway. The ceiling was removed. These controls remain:

| | |
|---|---|
| global bucket, in process | flood and CPU protection |
| failures per address | one source guessing at many accounts |
| failures per account | many sources guessing at one account |

## A million people

This ran on the same laptop, busy with other work, with the database on it over
loopback. It compared two databases, measured before the fixes below:

- 1,000,000 people in 1,000 organisations, with 1,000,000 sessions and 5,000,000
  audit events, 2.6 GB;
- one person in the same 1,000 organisations.

Four workers ran each operation. The figures are the median of two runs, in
milliseconds:

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

The size of the directory does not show in these. That is the result, and what it
took to be able to say so is below. Everything was found by counting the rows read
by sequential scan during the run, rather than by the clock:

- **On every sign-in.** An organisation's budgets were read through the text of
  its key, which no index serves. The instance's first organisation was read and
  sorted twice. Neither shows at one organisation, and both grow with the number
  of organisations.
- **On every janitor pass.** Retention read every session. The audit head read the
  trail, 3.4 s at five million events, every minute for the life of the
  deployment.

The second list was longer than the seed could show. Five more sweeps had no
index, on tables that were only cheap because nothing had been put in them.

So the tests now run a real pass and a real sign-in past the planner. They ask of
each statement whether any index could serve it, rather than keeping a list of
statements somebody remembered.

This is one node on one machine, so read it for the shape. A sign-in makes many
round trips, and what a network between the engine and its database does to it is
not in these numbers. The next section is.

## Three nodes, a million people, the database across the network

This was measured in November 2026, on two rented Linux machines in one data
centre. Each was an AMD EPYC 9655P, with 16 threads and 32 GB.

One machine held PostgreSQL 17 alone. The engines reached it over Transport Layer
Security ([TLS](glossary.md#tls)), with a scram-sha-256 password. A `SELECT 1` on
one connection took 0.121 ms at the median, and 0.126 ms at p99. Over the day the
median moved between 0.05 and 0.12 ms. So this is a local area network (LAN) in
one data centre, and not a database in another region.

The other machine ran three engine processes, each on two physical cores of its
own. They sat behind nginx, which dealt requests to them round-robin on loopback.
The load driver ran on the remaining two cores.

The data was 1,001 organisations, 1,000,000 people, 1,000,000 sessions and
10,000,000 audit events, 5.1 GB.

Sixteen workers ran a 10-second warm-up, then five rounds of 15 seconds of each
operation. The table gives the mean of the rounds with its 95% interval. The p99
is the mean of the rounds' p99. No round had an error or a 429, and no node logged
an error:

```
                         ops/s              p50 ms    p99 ms
discovery                27,433 ± 1,077      0.45      2.37
client credentials       21,415 ±   274      0.66      1.86
introspection            17,574 ±   974      0.89      1.85
sign-in                     274 ±     6     54.65    121.43
refresh                   9,867 ±   144      1.54      3.19
userinfo                 19,359 ± 2,175      0.63      2.20
```

A sign-in crosses the nodes. The authorization request, the password, the consent
and the code each reach whichever node the balancer picks, and every one finished.
It is Argon2id that sets its price, as on one machine.

Two settings were changed for the run. Each refusal that led to them was the
engine doing what it should:

- **Sign-in took turns through 1,000 people.** With sixteen workers signing one
  person in together, every refusal in the audit trail was
  `{"reason": "throttled"}`. Each attempt is charged to the account before the
  password is checked, so sixteen at once look like guessing.
  `bench run -signin-people` makes each sign-in somebody else.
- **The organisation's budgets were raised** to their maximum, with
  `signari instance org-budgets`. That is 1,000,000 tokens and 1,000,000 sign-ins
  a minute. At the defaults, 6,000 tokens and 1,200 sign-ins, the warm-up alone
  spent the sign-in budget, and the next sign-in was a 429.

PostgreSQL's data was on tmpfs, a file system held in memory. The machines' own
disk stalled commits for up to 1.5 seconds at a time (`pg_test_fsync` measured 2
synced writes a second at worst). Every token-issuing worker stopped together,
while discovery, which writes nothing, did not.

With the data in memory, a commit still runs PostgreSQL's own path, `fsync` and
`synchronous_commit` on, at no cost. A deployment's disk adds its own flush time
to everything that writes.

The driver had two cores, so the cheapest operations may be held by the driver
rather than the nodes. The one-machine table above compares one person with a
million. This one is a different shape, and it is not a before-and-after.

The run is in [the scale bench](../tools/bench/scale/README.md),
`tools/bench/scale`. `database.sh` and `seed.sql` run on the database's machine,
and `nodes.sh` on the nodes'.

It was run again from those scripts on a second, fresh pair of machines. Every
operation came within the first run's interval, still with no errors. Client
credentials ran at 20,673 ± 891 a second, sign-in 281 ± 3, refresh 9,809 ± 216.

## A hundred thousand people

This used one client over loopback, on the same laptop, busy with other work at
the time. It ran against one organisation of 100,000 people, each linked to a
System for Cross-domain Identity Management ([SCIM](glossary.md#scim)) source,
and 100,000 relations:

```
SCIM, 100 people a page     first page   p50  9 ms   p99 40 ms
                            middle       p50 15 ms   p99 66 ms
                            last page    p50 21 ms   p99 64 ms
AuthZEN, 100 evaluations    one request  p50  2 ms   p99 7-11 ms, five statements
```

The same measurements were made again in November 2026, on a rented Linux
machine (AMD EPYC 9655P). The engine and PostgreSQL shared four physical cores,
and the client ran on four others, against one organisation of 100,000 people.
Each page shows the median p50 and the worst p99 of three runs of 200 requests.
The Lightweight Directory Access Protocol ([LDAP](glossary.md#ldap)) line is five
rounds of 15 seconds:

```
SCIM, 100 people a page     first page   p50  5.6 ms   p99  8.8 ms
                            middle       p50  7.5 ms   p99 12.5 ms
                            last page    p50  9.8 ms   p99 14.6 ms
SCIM, a group PUT replacing all 10,000 members              0.23 s
LDAP, one person found among 100,000, 16 clients      p50 0.79 ms   p99 2.30 ms   18,307 a second
```

Every page costs two walks of the whole source. One is the count `totalResults`
requires (RFC 7644 §3.4.2), and the other is the offset to the page, an
index-only scan. RFC 7644 is the Request for Comments that defines the SCIM
protocol.

On a table loaded seconds before, with no vacuum yet, the same last page was p50
22 ms and p99 27 ms. Every row the two walks pass was still read from the table,
to see whether it was visible. Autovacuum fixed that within a minute, and the
figures above are from after it.

The [AuthZEN](glossary.md#authzen) evaluations were 17 ms until this was measured.
A batch named its subject once per question, and the join found their relations
once per mention. So a hundred questions cost twelve times what ten did, on the
same five statements. Counting statements, which a test does, could not see it.
The lists are made distinct now.

Getting to a hundred thousand people found more than the measurements did,
because it took over half an hour and was not finished. Bringing people in took
time that grew with the square of how many, and only on a deployment that had
never held any:

| | before | after |
|---|---|---|
| one statement, 20,000 people, new deployment | 103 s | 1.3 s |
| the same, into an organisation of 100 | 243 s | 1.1 s |
| a realm import of 16,000 people, new deployment | 267 s | 17 s |

There were three causes, each hidden from a test by a database that already had
statistics in it:

- The check that an address is nobody's username made one plan for the whole
  statement, on a table with nothing to go on. The plan read the organisation for
  every row.
- An import's own lookups did the same, for the length of its transaction.
- The command line's version bump updated one row for every statement, which a
  transaction cannot prune behind itself. So each update walked past all the ones
  before it.

A first directory sync is one such statement, and an import is what a migration
begins with. So a new deployment was the worst place for this to be slow.

## A page of the Admin API

This ran on the same laptop, with four workers over loopback TLS, and one
organisation of 100,000 people. It read a page of 100 at a time, with the
per-token limit raised out of the way. There were several runs of each, code
before and after, on the same setup:

| | before | after |
|---|---|---|
| pages a second | 4-18 | 2,070-2,970 |
| p50 | 236-795 ms | 1.3-1.6 ms |
| p99 | 444-2,356 ms | 3-7 ms |
| buffers read for a page | 2,703 | 104 |
| buffers for a page halfway through | 2,619 | 105 |

Every page read all 100,000 people and sorted them, for one row or a hundred.
`SELECT id::text ... ORDER BY id` orders by what the select list calls `id`,
which is the text, and no index holds that. And `id::text > $1` is not a seek, so
a later page walked from the start.

Neither shows on a table a test can fill, and the first run of the load driver
found both. The people, group, group member, invitation and client lists all page
by the key now. A test runs every read the Admin API has past the planner.

By default a token gets 50 requests a second (`SIGNARI_ADMIN_TOKEN_RATE`). So that
is what a deployment will see, and it is now the limit, not the database.

That test found three more that a page never showed. All three have indexes now:

- A deployment-wide read of the audit trail sorted the whole trail, because
  nothing led with its time.
- The list of event subscriptions counted its way through every delivery, once
  for each subscription.
- A Duo integration counted its enrolments through the whole table.

Two things went wrong measuring this, and they are the reason for "the same
setup".

The first runs of the fixed code answered 44 a second. Nothing had analysed the
table since it was filled, so the planner took 100,000 rows for a handful. A real
table has statistics by then, and a load test run straight after a bulk load does
not. So analyse first.

And a batch of three runs read a quarter of the others, for no reason anyone
found. That is why two builds are measured in turn, and more than once, before
anything is believed.

Recording a token's use on every request looked like the cause of the 44. It was
not. With it and without it, in turn, the runs overlap, and it stayed as it was.

## Everything else a deployment does

None of this had ever been measured. It used the same machine and 100,000 people.
The engine ran against a real upstream built into the load driver: an OpenID
provider, a SCIM server and a directory. There were two or three runs of each with
no errors, but for the two long runs at the end:

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

In the table, Client-Initiated Backchannel Authentication
([CIBA](glossary.md#ciba)) is a sign-in that the person approves on another
device. A time-based one-time password ([TOTP](glossary.md#totp)) is the code an
authenticator app shows.

The two lines with no rate are the one request of a sign-in, with the password
hash before it kept out of the time. A pushed request and a device start are
paced at 6,000 a minute per client, which is 100 a second through one
application. So those lines are short windows under that, and not rates to
sustain.

Measuring these found three things that were wrong, which is more than the
numbers did.

**A sign-in through a provider that began at an application ended at a 404.**
After the upstream sign-in, the engine sent the person to `/authorize`. It serves
`/oauth2/authorize`. Every earlier check of a provider stopped at
the session. The test beside the code had the same wrong path written out, so it
passed. It took a driver that insists on a redeemed code at the end. The router
now vouches for every path written down for a browser.

**Starting a device sign-in had no limit.** It answered 3,000 a second, each one a
row that lives ten minutes. The client authenticates nothing when it is public. A pushed request had been fixed for exactly that, and this had not. It is
paced the same way now.

**A SCIM sync with nothing to do took 325 seconds.** That was eight times what
creating everybody had taken moments before. The links it had written had not been
counted yet. So the planner took 100,000 rows for a handful, and walked all of
them per person. A sync that writes many links counts them now, and the same run takes 262
milliseconds.

## Round trips on the token paths, November 2026

The token endpoint, introspection and revocation spent more of their time waiting
on the database than computing. Every decision a request needs is still read on
that request:

- Whether the client is enabled, and its organisation in service.
- Whether the token or its session has been revoked.
- Whether the caller has spent its guesses.

What changed is how many round trips that takes. The client and its two failure
counters are read in one.

Introspection asks the token's standing in that same round trip. The token is
verified first, against the keys in memory, so that nothing is read on behalf of a
caller that has not authenticated.

Tokens that arrive while their organisation's budget is being charged are charged
together by the next statement. Each is answered from its own place in the count,
so the limit is exactly what it was.

A client revoking its own access token is one statement. The audit record is
written apart, so that a record that cannot be written never undoes a revocation.

Four physical cores were shared by the engine and PostgreSQL (data on tmpfs,
`fsync` on), and the driver ran on four others. Sixteen workers ran, with the old
build and the new taking turns in 15-second windows, five turns each. The figures
are the mean and 95% interval:

```
                                before            after
client credentials              3,701 ± 103       5,274 ± 258     +42%
introspection                   2,250 ±  40       2,777 ± 106     +23%
a token issued and revoked      1,165 ± 113       1,465 ± 227     +26%
```

The same night, two more cuts were measured on the same machine.

A device that is waiting for a person to approve it is now answered in one
statement a poll. Each poll was a transaction of four round trips. The rate went
from 2,897 polls a second to 3,764 (+30%). That was over three turns of five
rounds each, with the two builds taking turns on one database.

A sign-in through an upstream provider had been opening a new connection to the
provider for every sign-in, and leaving it open. It now uses the same connections
throughout. It went from 228 a second, with 6,142 sign-ins failed for want of a
port, to 292 with none.

## Audit records written together, November 2026

The audit chain's lock is held until the commit. So records written in
transactions of their own took turns at the commit itself. On this machine that
was 2,223 a second from one writer and 2,152 from sixteen, where plain inserts
reached 17,670. A token exchange, a backchannel request and a revocation each
write their record that way.

Records that arrive while one is being written are now appended together, in one
statement and one commit. Each is hashed after the one before it, as before, and
each is committed before its request is answered ([the audit
chain](audit-chain-fork.md#the-fix)).

The method was the same as above, on the same machine. The two builds took turns
on one database at the new schema, five turns each:

```
                                before      after
token exchange                  1,876       2,322     +24%
CIBA start                      1,920       2,059     +7%
a token issued and revoked      1,726       1,780     within its turns' spread (1,597 to 1,925)
jwt-bearer (writes no record)   2,124       2,140     level, as it should be
```

The chain verified afterwards over all 1,201,088 entries the run had appended, by
both builds in turn.

## The database connection, November 2026

A CPU profile of the engine under these cells put a fifth of its time in TLS,
under the database driver's writes. The connection string named no `sslmode`, so
the driver used its default, `prefer`, and PostgreSQL on the same host offered
TLS.

The same binary ran with the two connection strings taking turns on one database,
five turns each:

```
                       sslmode=prefer (TLS)   sslmode=disable
sign-in via provider          315                  358        +14%
token exchange              2,248                2,496        +11%
device poll                 5,327                5,897        +11%
client credentials          6,388                6,522         +2%
```

These ran over TCP on loopback, not a Unix socket, which was not measured. Across
a network, the connection stays encrypted and verified (`sslmode=verify-full`).
See [configuration](configuration.md).

## The sign-in page, November 2026

On a sign-in through an upstream provider, the same profile put 6% of the engine's
CPU in one decision. On every render of the sign-in page, it decided whether the
sign-in flow takes an emailed code. That answer depends on the flow alone, and a
loaded flow now keeps it once worked out.

Counting each request's statements then showed something else. An authorization
request that renders the page read its client 8 times in 18 statements. The page
asks whose it is several times over, and only the sign-in page's own handlers kept
the answer for the request. Every render keeps it now, and the instance's first
organisation with it.

These are sign-ins through a provider, each change against the build before it,
taking turns on one database as above:

```
                                              before    after
the flow keeps its answers                      321       339    +6%
the page keeps whose it is                      329       382    +16%   (p50 48.6 → 41.9 ms)
and the first organisation, once a render       390       396    within its turns' spread
```

Device polls, which render no page, were measured alongside as the control:
level, 95% and 102%.

What the page decides from was then still read a statement at a time. That is
what it wears, its provider buttons, and whether it links sign-up, keeps a person
signed in, routes by address and offers passkeys.

Those statements now go in one batch, each the one its own reader asks, still on
every render. So a change shows on the next page. If any of them fails, they are
asked one by one as before. The sign-in page went from 9 round trips to 4, and an
authorization request that renders it from 11 to 5.

These are sign-ins through a provider, on another machine of the same kind with
the database on disk, the two builds taking turns:

```
                                              before    after
the page's settings in one round trip           343       373    +9%    (p50 46.1 → 42.3 ms)
device polls, the control                     3,899     3,863    level
```

## Reproducing

The harness is [the bench tool](../tools/bench/README.md), in `tools/bench`. It
runs full flows, reports latency percentiles, and counts load shed separately from
failures.

That distinction matters. A 429 is the engine working, and counting it as a
failure hides whether anything is actually broken. Until October 2026 the harness
was a file in a session scratchpad that nobody else could run.

## What this is not

It is not a benchmark. It is one laptop, one instance, one database, no TLS, and a
password chosen to be found in the cache. Treat it as a floor and a shape, rather
than a number to put on a page. The shape is that sign-in costs Argon2, and
everything else is cheap.
