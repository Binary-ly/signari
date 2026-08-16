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

## What this does not do yet

- **Policy cache coherence.** Each instance caches the policy file and reloads
  on an interval, so for that interval two instances can enforce different
  versions. Bounded and small, and not yet coordinated.
- **CAPTCHA counters** are still per-instance, so adaptive mode escalates later
  than configured when spread across instances. Same class of bug as the one
  above, smaller blast radius, same fix available.
- **Outbox delivery** is not partitioned. Two instances can attempt the same
  logout notice; delivery is idempotent at the relying party's end by `jti`,
  but the duplicate work is real.

Each is listed because it is known, not because it is fine.
