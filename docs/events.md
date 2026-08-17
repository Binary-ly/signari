# Event subscriptions

Telling other systems what happened here.

```sh
signari events subscribe -org <uuid> -name siem \
  -url https://siem.example/hooks/signari \
  -events login.failed,impersonation.started
```

The signing secret is printed **once**. It is stored sealed with the root key and
never shown again, so a database copy is not a licence to forge events — an
operator who loses it rotates rather than reads.

```sh
signari events list -org <uuid>
```

## Deliveries go through the outbox

Posting from the request path makes every sign-in as slow and as reliable as the
slowest subscriber, and an event whose subscriber was down is simply lost. That
is the failure mode of every "notification webhook" that is really a goroutine
and a hope.

The outbox already had attempts, capped backoff and parking, because
back-channel logout needed them. Events use the same machinery:

- The event and the intent to deliver it **commit in the same transaction**. There
  is no window where the log says something happened and nothing was ever sent.
- One outbox row **per (event, subscriber)**. A slow subscriber cannot hold up a
  fast one, and a permanently failing one can be parked alone.
- After 10 consecutive failures — roughly a day under capped backoff — the
  subscription is **disabled with the reason recorded**, visible in
  `signari events list`. A subscription that stopped working is a fact, not a
  silence.

## Every delivery is signed

```
Signari-Signature: t=1786972759,v1=<hex hmac-sha256>
Signari-Event-Id: ev_9f2a…
Signari-Event-Type: login.failed
```

`v1` is HMAC-SHA256 over **`<t>.<raw body>`** — the timestamp and the body joined
by a full stop, with that subscription's secret.

**The timestamp is inside the MAC.** Signing only the body means a captured
delivery can be replayed forever and a subscriber cannot tell a live event from
last month's. With `t` covered, changing it invalidates the signature, so a
subscriber can refuse anything older than a few minutes and mean it.

**The separator matters.** Without it, `(t=1, body="23")` and `(t=12, body="3")`
produce the same MAC — a signature ambiguous about what it signed is not a
signature.

The scheme is deliberately the one Stripe uses. A subscriber's engineers have
almost certainly implemented it before, and a verification routine somebody
already got right is worth more than an original one.

## The URL is treated as hostile

A webhook URL is a place the identity provider will make a request, to an address
somebody else chose. That is a proxy inside the trust boundary, and the classic
use of one is to reach what the attacker cannot: `169.254.169.254` for cloud
instance credentials, `127.0.0.1` for the admin API, `10.0.0.0/8` for the rest of
the VPC.

So the check is **at dial time, not at save time**. Validating the hostname when
the subscription is saved checks a *name*; the request is made to an *address*,
and the two are joined by DNS, which the name's owner controls. A host that
resolves publicly when checked and to `169.254.169.254` when dialled defeats any
amount of URL parsing — that is DNS rebinding, and it is not exotic.

Refused: loopback, RFC 1918, link-local, multicast, unspecified, unique-local
IPv6, and the same addresses wearing an IPv4-mapped IPv6 shape (`::ffff:127.0.0.1`).
Every redirect hop is dialled through the same check, and a redirect from https
to http is refused outright.

`https` only, enforced by a CHECK constraint as well as at save time.

## The response is not an instruction

Any 2xx is success; everything else is a failure, **including 410 Gone**. A
subscriber that means "stop sending" says so by having its subscription removed.
Treating a status code as an unsubscribe instruction lets anyone who can answer
that URL turn the events off.

The body is drained and discarded. A webhook response is not an instruction, and
reading one is how a subscriber starts driving the identity provider.

## At-least-once

A network that eats the response after we sent it is indistinguishable from one
that ate the request, and retrying is the only safe reading. `Signari-Event-Id`
is stable across retries, so a subscriber can be idempotent without parsing the
body.

## Which events

Every audited event is publishable — the fan-out lives inside `audit.Write`, so
no code path can record an event without it being deliverable. Dozens of places
record events; a fan-out written at each is one missing from some of them, found
by an operator whose alerting never fired for the one type that mattered.

Filtering is per subscription. `-events` empty means every event in the
organisation, which is a choice an operator makes rather than a default they
inherit. Matching is exact: subscribing to `login` does not quietly subscribe you
to `login.failed`.
