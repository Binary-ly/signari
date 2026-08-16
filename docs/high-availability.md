# Running more than one instance


Every instance connects to the same PostgreSQL and serves the same issuer. There
is no leader election to configure, no cache to invalidate, and no sticky
sessions to arrange at the load balancer.

```sh
# Instance A and instance B, same DSN, same root key, same issuer.
SIGNARI_DSN=… SIGNARI_ROOT_KEY=… SIGNARI_ISSUER=https://id.example.com \
  signari serve -addr 0.0.0.0:8080
```

## What was already shared, and what was not

Signing keys, sessions, authorization codes, refresh families, consent, device
codes and audit all live in the database, so two instances agree about them
without doing anything. Verified: both instances serve identical `kid`s, and a
token minted by one verifies at the other.

The janitor coordinates with a transaction-scoped advisory lock — one instance
sweeps, the others record `Skipped`, and a node that dies mid-pass releases the
lock by rolling back rather than leaving the janitor wedged.

**Rate limiting did not.** It was a token bucket in process memory.

## The measurement

```
                     40 sign-in attempts
one instance         26 allowed, 14 refused
two instances        40 allowed,  0 refused      ← the limit stopped binding
```

Every instance added for availability multiplied the brute-force budget by one.
A deployment that scales out to survive traffic quietly weakens the defence that
matters most — and nothing about it looks wrong from inside either process.

After:

```
one instance         20 allowed, 20 refused
two instances        20 allowed, 20 refused      ← the same number either way
```

## It was also global, which is a separate bug

One bucket for every sign-in in the deployment meant a single attacker could
exhaust it and rate-limit **everybody**: a denial of service costing one script.
Meanwhile guessing spread across many accounts was never counted per account at
all.

Both fall out of the same fix — counters keyed by what is being limited, held
where every instance can see them:

| key | limit | stops |
|---|---|---|
| `signin:ip:<address>` | 20 per 5 min | one source grinding through many accounts |
| `signin:user:<identifier>` | 30 per 15 min | many sources grinding through one account |

The address comes from the socket, never from `X-Forwarded-For`: honouring a
header set by the caller would let an attacker spend somebody else's budget and
keep their own.

### The per-account limit is a real tradeoff

That key is chosen by whoever submits the form, so any per-account limit is a
way to degrade one named person's sign-in on purpose. It is bounded two ways:
the number is high enough that a real user never reaches it, and it is a **rate
limit that expires by itself**, not a lockout needing an administrator. Fifteen
minutes of slower sign-in is a far smaller harm than an account somebody has to
be talked out of.

Both limits answer identically. Saying which one was reached would tell an
attacker whether the account exists.

## Why a fixed window and not a token bucket

A token bucket needs read-then-write: refill by elapsed time, then decrement.
Two concurrent requests can both read the same value and both write their own
result, so a decrement is lost and both are allowed — it leaks under exactly the
load a limiter exists for.

A fixed window increments **inside** the `UPDATE`, referencing the stored row,
so the row lock handles concurrency and no read is lost. Tested with 100
concurrent requests against a limit of 20: exactly 20 allowed.

The cost is the boundary: a caller can spend a full window at the end of one and
again at the start of the next, so the worst case is 2× across a moment. That is
bounded and stated, as against a multiple that grew with the size of the
deployment.

## One process-local bucket remains, on purpose

A generous in-process guard still runs first on the sign-in path. Its job is
protecting the database from a flood, not bounding guesses — the shared limits
cost a round trip each, and an unbounded flood of them is its own denial of
service. It is set high enough that a real deployment never sees it and an
attacker reaches the keyed limits instead.

The same reasoning keeps JWKS on a local bucket: high volume, nothing expensive
behind it, and no security decision resting on the count.

## Failing closed

If the database cannot be reached, a sign-in attempt is **refused**, not waved
through. Signing in needs the database one query later anyway, so failing closed
costs nothing that was going to work — while failing open would turn a database
blip into an unlimited guessing window.

## The CAPTCHA counter had the same bug

Adaptive mode counts failures per address and challenges after a threshold. That
counter was a map in process memory, so with N instances an attacker needed N
times the failures before any single one escalated — and with an even spread
across a load balancer, **none of them ever would.** Adaptive mode silently
stopped being adaptive.

It now uses the same shared counters. `internal/captcha` gained an interface
rather than a database dependency: it is small and pure and should stay
testable without one, so the caller supplies an implementation backed by
whatever every instance can see.

Two properties are tested, because both can be got wrong:

```
three failures split across two instances → both instances see three
five reads of the counter                 → still three
```

The second matters more than it looks. The count is read on **every render** of
the sign-in page, so a counter that charged for reading would escalate its own
challenge by being displayed, and eventually challenge everybody who looked at
it.

A database error reads as **zero**, not as "challenge everybody": the sign-in is
about to fail for the same reason, and adding a puzzle to it helps nobody.

## Policy propagation, measured

Each instance caches the policy and reloads on a 30-second timer, so two
instances can briefly enforce different versions.

Measured rather than assumed. A deny rule was applied on one instance's
database, then both were polled:

```
t+05s  A=400  B=400   ← both refusing, with the operator's own message
```

Worst case is the 30-second window; in practice both had reloaded on the first
poll. That bound is small enough that a `LISTEN`/`NOTIFY` channel — and the
long-lived connection it needs — is not worth its complexity for a
configuration change. It would be worth it for an emergency revocation, and
revocation does not go through this path: sessions and tokens are read from the
database on use.

## Outbox delivery: correct, and holding a connection for four minutes

The claim was already right — `FOR UPDATE SKIP LOCKED` divides the work, so two
instances never deliver the same notice. The previous version of this page said
otherwise; that was wrong.

What was wrong in the code was the transaction boundary. The whole drain ran
inside **one** transaction: claim, then every HTTP call with those row locks
held and a pooled connection checked out. A batch of 25 against dead receivers
held a database connection for up to **250 seconds**, and the pool is shared
with everything else the engine does.

Now three phases — claim, deliver, record — with no transaction open across the
network, and delivery bounded at 8 concurrent POSTs so one hanging receiver no
longer delays every notice queued behind it.

Keeping the two instances apart after the locks are released is the other half:
claiming pushes `next_attempt_at` forward by a lease. Without that, committing in
order to deliver outside a transaction hands the same rows straight to the other
instance. `attempts` is deliberately not incremented on claim — a crash between
claiming and recording is not the relying party failing to answer, and charging
it as one would march a perfectly reachable receiver toward being parked.

Tested: two instances draining at once deliver each notice exactly once; a row
being delivered is not locked; a slow receiver does not delay the others.

### The twin that kept the bug

There are two drains — logout notices and security events — written
independently on purpose, with a comment saying a shared helper would invite one
to be tuned for the other.

That reasoning was sound about **policy**: how long to back off, what to log,
which receiver to call. It was not sound about **mechanism**, and the cost
arrived immediately: the transaction-boundary fix went into the logout drain and
its twin kept the bug, because duplicated mechanism means a correctness fix has
to be remembered twice.

The boundaries now live in one place and the policy stays with each caller. The
security-event drain has its own test at that level, which is what it lacked —
and lacking it is exactly why nothing said it was still wrong.

## What running two instances actually found

**The audit chain forked whenever two events were written at once.** Two entries
claiming the same predecessor is indistinguishable from a deleted entry, so
verification reported tampering on data nobody had touched.

It was never specific to more than one instance — two concurrent sign-ins do the
same thing — but two made it frequent enough to notice. See
[the audit chain fork](audit-chain-fork.md).

That is the argument for this whole exercise: the bug was in a single-instance
code path, and only running the deployment shape we intend to support surfaced
it.

## What this still does not do

Nothing known. The three gaps listed when this page was written — policy cache
coherence, CAPTCHA counters, outbox partitioning — are measured, fixed, or shown
to have been a misreading, above.
