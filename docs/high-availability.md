# Running more than one instance

## Introduction

One Signari server is a single point of failure. When it stops, nobody can sign
in anywhere. To survive that, you run several copies of Signari behind a load
balancer.

Every instance connects to the same PostgreSQL and serves the same issuer. There
is no leader election to configure, no cache to invalidate, and no sticky
sessions to arrange at the load balancer. This page explains what the instances
share, and what had to change before two of them were as safe as one.

## Starting a second instance

Each instance needs the same database, root key and issuer. Start each one like
this:

```sh
# Instance A and instance B, same DSN, same root key, same issuer.
SIGNARI_DSN=… SIGNARI_ROOT_KEY=… SIGNARI_ISSUER=https://id.example.com \
  signari serve -addr 0.0.0.0:8080
```

## What was already shared, and what was not

Signing keys, sessions, authorization codes, refresh families, consent, device
codes and audit all live in the database. So two instances agree about them
without doing anything. This was verified: both instances serve identical `kid`s,
and a token minted by one verifies at the other.

The "janitor" is the background job that ends expired sessions and purges spent
authorization codes. It coordinates with a transaction-scoped advisory lock. One instance sweeps, and the others record
`Skipped`. A node that dies mid-pass releases the lock by rolling back, rather
than leaving the janitor wedged.

A pass is many short transactions rather than one long one. A batch is up to 500
sessions or 1,000 rows of a table. Each batch is committed on its own and takes
the lock again, and each kind of row gets a batch before any gets a second.

A sweep that fails stops only itself. At 45 seconds a pass stops starting
batches, and logs what it left. The next pass carries on, so a backlog after an
outage is worked through and nobody waits on it.

**Rate limiting did not.** It was a token bucket in process memory.

## The measurement

With the old limit, 40 sign-in attempts against one instance and against two
gave this:

```
                     40 sign-in attempts
one instance         26 allowed, 14 refused
two instances        40 allowed,  0 refused      ← the limit stopped binding
```

Every instance added for availability multiplied the brute-force budget by one. A
deployment that scales out to survive traffic quietly weakens the defence that
matters most. Nothing about it looks wrong from inside either process.

After the fix, the same attempts gave this:

```
one instance         20 allowed, 20 refused
two instances        20 allowed, 20 refused      ← the same number either way
```

## It was also global, which is a separate bug

One bucket for every sign-in in the deployment meant a single attacker could
exhaust it and rate-limit **everybody**. That is a denial of service costing one
script. Meanwhile, guessing spread across many accounts was never counted per
account at all.

Both fall out of the same fix: counters keyed by what is being limited, held
where every instance can see them:

| key | limit | stops |
|---|---|---|
| `signin:ip:<address>` | 20 per 5 min | one source grinding through many accounts |
| `signin:user:<identifier>` | 30 per 15 min | many sources grinding through one account |

The address comes from the socket, never from `X-Forwarded-For`. Honouring a
header set by the caller would let an attacker spend somebody else's budget and
keep their own.

### The per-account limit is a real tradeoff

That key is chosen by whoever submits the form. So any per-account limit is a way
to degrade one named person's sign-in on purpose. It is bounded two ways:

- The number is high enough that a real person never reaches it.
- It is a **rate limit that expires by itself**, not a lockout needing an
  administrator.

Fifteen minutes of slower sign-in is a far smaller harm than an account somebody
has to be talked out of.

Both limits answer identically. Saying which one was reached would tell an
attacker whether the account exists.

## Why a fixed window and not a token bucket

A token bucket needs read-then-write: refill by elapsed time, then decrement. Two
concurrent requests can both read the same value, and both write their own
result. Then a decrement is lost and both are allowed. It leaks under exactly the
load a limiter exists for.

A fixed window increments **inside** the `UPDATE`, referencing the stored row. So
the row lock handles concurrency, and no read is lost. Tested with 100 concurrent
requests against a limit of 20, exactly 20 were allowed.

The cost is the boundary. A caller can spend a full window at the end of one and
again at the start of the next. So the worst case is 2× across a moment. That is
bounded and stated, as against a multiple that grew with the size of the
deployment.

## One process-local bucket remains, on purpose

A generous in-process guard still runs first on the sign-in path. Its job is
protecting the database from a flood, not bounding guesses. The shared limits
cost a round trip each, and an unbounded flood of them is its own denial of
service.

It is set high enough that a real deployment never sees it, and an attacker
reaches the keyed limits instead. The bound is half again what the machine can
hash. It is measured when the engine starts, with the cost new hashes are made
with, and is never less than 100 a second.

It was a fixed 100, which four cores' worth of sign-ins already exceeded. How many
hash at once is the hasher's own bound. So sign-ins beyond what the machine can
hash wait for a slot.

The same reasoning keeps the JSON Web Key Set ([JWKS](glossary.md#jwks)) on a
local bucket. It has high volume, nothing expensive behind it, and no security
decision resting on the count.

## Failing closed

If the database cannot be reached, a sign-in attempt is **refused**, not waved
through. Signing in needs the database one query later anyway, so failing closed
costs nothing that was going to work. Failing open would turn a database blip into
an unlimited guessing window.

## The CAPTCHA counter had the same bug

A CAPTCHA is a puzzle that tells a person from a script. Adaptive mode counts
failures per address, and shows the puzzle after a threshold.

That counter was a map in process memory. So with N instances, an attacker needed
N times the failures before any single one escalated. With an even spread across
a load balancer, **none of them ever would.** Adaptive mode silently stopped being
adaptive.

It now uses the same shared counters. `internal/captcha` gained an interface
rather than a database dependency. It is small and pure, and should stay testable
without one. So the caller supplies an implementation backed by whatever every
instance can see.

Two properties are tested, because both can be got wrong:

```
three failures split across two instances → both instances see three
five reads of the counter                 → still three
```

The second matters more than it looks. The count is read on **every render** of
the sign-in page. A counter that charged for reading would escalate its own
challenge by being displayed, and eventually challenge everybody who looked at it.

A database error reads as **zero**, not as "challenge everybody". The sign-in is
about to fail for the same reason, and adding a puzzle to it helps nobody.

## Policy propagation

Every instance asks the database which access policy is in force on every
decision. That is one indexed row: the document's digest, and the document itself
only when the digest has changed. So a new rule applies on the next request, on
every instance, and no two instances enforce different versions.

This page used to describe a 30-second reload timer, measured at five seconds in
practice and judged small enough. The judgement was wrong for this case. A rule
can say `deny: true`, and this engine never serves a security-negative decision
from a snapshot.

A deny rule written to shut a client out must work on the next request. It must
not wait up to half a minute on whichever instance the attacker's request happens
to reach. Parsing is still memoised, so the cost is the digest query, not a
parse.

## Outbox delivery: correct, and holding a connection for four minutes

The "outbox" is the queue of notices Signari delivers to other services, such as
sign-out notices and security events. The claim was already right:
`FOR UPDATE SKIP LOCKED` divides the work, so two instances never deliver the
same notice. The
previous version of this page said otherwise, and that was wrong.

What was wrong in the code was the transaction boundary. The whole drain ran
inside **one** transaction: claim, then every HTTP call with those row locks held
and a pooled connection checked out. A batch of 25 against dead receivers held a
database connection for up to **250 seconds**. The pool is shared with everything
else the engine does.

Now there are three phases, claim, deliver and record, with no transaction open
across the network. Delivery is bounded at 32 concurrent POSTs, so one hanging
receiver no longer delays every notice queued behind it.

Event deliveries work the same way. They kept the old shape longest, one
transaction across 32 calls in a row. Each kind of delivery has a goroutine of its
own, so a receiver that is down holds up nothing but its own kind. Each drains
until its queue is empty, rather than taking one batch every two seconds.

Keeping the two instances apart after the locks are released is the other half.
Claiming pushes `next_attempt_at` forward by a lease. Without that, committing in
order to deliver outside a transaction hands the same rows straight to the other
instance.

`attempts` is deliberately not incremented on claim. A crash between claiming and
recording is not the application failing to answer. Charging it as one would
march a perfectly reachable receiver toward being parked.

This was tested. Two instances draining at once deliver each notice exactly once.
A row being delivered is not locked, and a slow receiver does not delay the
others.

### The twin that kept the bug

There are two drains, one for sign-out notices and one for security events. They
were written independently on purpose, with a comment saying a shared helper would
invite one to be tuned for the other.

That reasoning was sound about **policy**: how long to back off, what to log,
which receiver to call. It was not sound about **mechanism**, and the cost
arrived immediately. The transaction-boundary fix went into the sign-out drain, and
its twin kept the bug. Duplicated mechanism means a correctness fix has to be
remembered twice.

The boundaries now live in one place, and the policy stays with each caller. The
security-event drain has its own test at that level, which is what it lacked.
Lacking it is exactly why nothing said it was still wrong.

## What running two instances actually found

**The audit chain forked whenever two events were written at once.** Two entries
claiming the same predecessor is indistinguishable from a deleted entry. So
verification reported tampering on data nobody had touched.

It was never specific to more than one instance, since two concurrent sign-ins
do the same thing. But two instances made it frequent enough to notice. See [the
audit chain fork](audit-chain-fork.md).

That is the argument for this whole exercise. The bug was in a single-instance
code path, and only running the deployment shape Signari intends to support
surfaced it.

## Configuration read once at startup

The signing keys were not the only thing loaded once and never re-read. The same
sweep over `serve()` found the Remote Authentication Dial-In User Service
([RADIUS](glossary.md#radius)) device list. Its consequence was worse than
inconvenience: **revoking an access point did nothing until a restart.** The
listener carried on answering a device whose access had been withdrawn.

Two halves of one gap were both missing:

- There was no command to revoke a device at all. The `enabled` column existed,
  so it could only be done by editing the database by hand.
- Doing so had no effect on anything already running.

These commands now revoke a device and restore it:

```sh
signari radius disable-client -name office-ap
signari radius enable-client  -name office-ap
```

Devices are re-read every minute. This was measured on a running listener: an
access point authenticating normally was revoked, and refused ~70 seconds later
with no restart.

### A guard that blocked the feature it shipped with

The first version of the reload refused an empty device list. The reasoning was
that a server trusting nobody is a total outage. An empty result also seemed more
likely to be a failed read than a deliberate removal.

That reasoning is borrowed from the directory sync, where an empty fetch really
can mean a paginated read that stopped early. **It does not transfer.** A single
SQL query either succeeds or returns an error; there is no partial success to
mistake for emptiness.

So the guard rejected exactly the reload that would have applied the revocation
of the last device, and revoking it did nothing. It was caught by testing the
feature end to end, rather than by testing the function.

An empty list is now honoured and logged at WARN. "No devices" means network
sign-in is off for everybody, and that should be visible without going looking.
Startup still refuses an empty list. A listener coming up with nothing configured
is almost certainly a misconfiguration. Saying so immediately is more useful than
serving a port that answers no one.

## A read replica, for the audit trail

`SIGNARI_READ_DSN` points the Admin API's `GET /admin/audit-events` at a replica,
and `signari export audit -dsn` takes one too. Reading the trail is the long read
an administrator makes, and it is append-only. So a replica that lags is only
missing the newest events. If the replica does not answer, the primary does, and
the log says so.

It is that and nothing else, on purpose:

- **Nothing that decides anything.** A session, a token or a client is read from
  the primary. A revocation a replica has not heard of yet is an authentication
  that should have been refused.
- **No list that carries an `ETag`.** A list answered from behind the primary
  would carry a version the primary has moved past. `If-Match` exists so that an
  apply cannot overwrite a change it never saw.

## More instances on one machine

This measures client credentials against one database, with 16 workers shared
between one load generator per instance. It is the median of two runs, with
everything on one 8-core laptop under other load:

```
instances   tokens/s    errors
1           2,864       0
2           2,657       0
4           2,969       0
```

The numbers are flat, because the machine is what ran out. The engines,
PostgreSQL and the load generators were sharing eight cores. So this says that a
second and a fourth instance cost nothing in coordination. That is what they
should cost, as nothing is shared between them but the database. It does not say
how far they scale, which needs hosts of their own.

## What this still does not do

Issuer aliases were read once at startup, which made a retired alias go on being
accepted until every instance restarted. They are now read per request, like
every other decision about what to accept.

The three gaps listed when this page was written were policy cache coherence,
CAPTCHA counters and outbox partitioning. Each is measured, fixed, or shown to
have been a misreading, above.
