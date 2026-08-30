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

### Verifying a delivery

```go
func verify(secret, header string, body []byte, tolerance time.Duration) error {
	var ts, sig string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}

	// The timestamp is checked BEFORE the MAC and again after. Before, so a
	// replay costs nothing to reject; the MAC covers `t`, so a replayer cannot
	// move the window without invalidating the signature it is replaying.
	secs, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("no timestamp")
	}
	if d := time.Since(time.Unix(secs, 0)); d > tolerance || d < -tolerance {
		return errors.New("outside the tolerance window")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)

	want, err := hex.DecodeString(sig)
	if err != nil {
		return errors.New("malformed signature")
	}
	// Constant time. A byte-by-byte comparison that returns early leaks how
	// much of a guess was right, and a MAC is exactly the value that makes
	// that leak worth harvesting.
	if !hmac.Equal(mac.Sum(nil), want) {
		return errors.New("signature does not match")
	}
	return nil
}
```

Three things this depends on that are easy to get wrong:

- **The RAW body.** Verify the bytes as received, before any JSON decode. Decode
  and re-encode and the key order, spacing and number formatting are your
  library's rather than ours, and a correct delivery fails to verify.
- **Reject before parsing.** An unverified body is attacker-supplied input; a
  handler that decodes first has already acted on it.
- **A tolerance you actually enforce.** A few minutes. Without one the timestamp
  is decoration and a captured delivery replays forever.

Signari's own implementation of this MAC is `Sign` in `internal/outbox`, exported
so a test can call the same function the sender uses. Two implementations of one
MAC is one implementation and one bug.

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


## Re-review against the Shared Signals Framework, August 2026

Version checked first: **Shared Signals Framework Specification 1.0, published 29
August 2025**. Current, and the version implemented against.

### Two defects, both the same mistake

The receiver was written against **RFC 8417 alone**. The Shared Signals Framework
is a *profile* of RFC 8417, and it is stricter in two places our code did not
know about.

**§4.1.7 — `exp` is forbidden, not merely discouraged.**

> The "exp" claim MUST NOT be used in SETs. The purpose is defense in depth
> against confusion with other JWTs, as described in Sections 4.5 and 4.6 of
> [RFC8417].

RFC 8417 §2.2 on its own only makes `exp` NOT RECOMMENDED, and our code cited
exactly that — then honoured the claim when present, refusing a SET whose expiry
had passed. That was a deliberate earlier fix, and the comment recorded why: a
transmitter that deliberately time-boxed an event had found us acting on it
afterwards.

Reasonable, and aimed at the wrong thing. **`exp` is not there to time-box an
event. It is forbidden so that a SET cannot be shaped like an ID token.** Once
that is the reason, honouring the claim is not enough — a SET with a comfortable
future expiry is exactly as confusable as an expired one, and ours accepted it.

**§4.1.2 — a top-level `sub` is forbidden, and we never checked.**

> The JWT "sub" claim MUST NOT be present in any SET containing an SSF event.

It sits under §4.1.3, *"Distinguishing SETs from other Kinds of JWTs — Of
particular concern is the possibility that SETs are confused for other kinds of
JWTs."* An SSF event names its subject in `sub_id`; a top-level `sub` is the
shape of an ID token.

We check `typ: secevent+jwt`, which is the primary confusion defence and which
would already refuse an actual ID token. The profile adds these two because typ
checking is not universal — defence in depth is its stated purpose, and we had
implemented one layer of it and not the other two.

Both are now refused outright. `Subject` is parsed as a `*string` so that
`"sub": ""` is distinguishable from an absent claim: an empty string is still a
`sub` claim.

| Mutation | Test that caught it |
|---|---|
| Honour `exp` instead of refusing it | `TestASETCarryingExpIsRefused` |
| Allow a top-level `sub` | `TestASETCarryingATopLevelSubIsRefused` |

### The lesson worth keeping

The previous review of this code checked it against RFC 8417 and RFC 8935 and
found five defects. It did not check it against the **profile** that governs it,
and the profile is where both of these live.

An implementation of a profiled specification has two documents to satisfy, and
the profile is the one that adds restrictions the base RFC calls optional. Citing
the base RFC in a comment — as ours did, accurately — is what made the gap look
like diligence.
