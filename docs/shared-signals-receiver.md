# Receiving Shared Signals

```
POST /ssf/receive
Content-Type: application/secevent+jwt
<the Security Event Token>
```

```sh
signari ssf add-source -org <uuid> -name "Upstream IdP" \
  -source-issuer https://idp.example.com \
  -source-jwks https://idp.example.com/oauth2/v1/keys \
  -source-audience https://id.example.com \
  -events https://schemas.openid.net/secevent/caep/event-type/session-revoked

signari ssf received -org <uuid>
```

## The half everybody skips

Every implementation that does Shared Signals **transmits**: "a session was
revoked here, tell the relying parties". That is the easy half and the one that
demos well.


## Conformance review against RFC 8417 and RFC 8935, August 2026

Reviewed against the **RFC texts**, not summaries. Four defects, two of them MUSTs:

| Finding | Where | Status |
|---|---|---|
| **Errors answered `401`.** RFC 8935 §2.3: *"When the SET Recipient detects an error parsing, validating, or authenticating a SET ... SHALL respond with an HTTP Response Status Code of 400"* | 8935 §2.3 | **fixed** |
| **No `Content-Language` header.** §2.3 says the error response **MUST** include one | 8935 §2.3 | **fixed** |
| **`exp` was ignored.** RFC 8417 §2.2: it is *"the time after which the JWT MUST NOT be accepted for processing"*. NOT RECOMMENDED in a SET, but not advisory when present — a deliberately time-boxed event was being acted on afterwards | 8417 §2.2 | **fixed** |
| **Multiple event entries were refused outright.** §2.2 forbids expressing multiple *independent* logical events; it permits several entries describing **one** event, which is how CAEP profiles convey detail. We were rejecting conforming transmitters | 8417 §2.2 | **fixed** |
| Unregistered error code `internal_error` | 8935 §2.4 | **fixed** |

### On the error-code decision

The `401`-with-a-uniform-body choice was deliberate: it avoided telling an
unauthenticated caller which issuers we are configured for. The RFC prescribes
`400` with **registered codes** that distinguish `invalid_issuer` from
`invalid_audience` from `invalid_key`.

We now follow the RFC. A partner whose transmitter is misconfigured has to be
able to tell *which* thing we rejected, and the residual disclosure — "this
deployment has a source for issuer X" — requires guessing an exact issuer URL to
learn. Interop and debuggability win that trade; the reasoning is recorded here
so the decision can be revisited rather than rediscovered.

### On multiple entries

The original concern — "partially applying a token leaves a state nobody can
reason about" — was right, and the remedy was wrong. Refusing rejected
conforming transmitters. Every entry is now applied **inside the one
transaction**, which is what actually makes partial application impossible.
Every entry must also be permitted: a source allowed to report one thing must
not smuggle another alongside it.

## The endpoint is unauthenticated, and that is correct

A transmitter pushes without credentials; **the signature is the credential**.
That is RFC 8935's model and it is the right one — a shared secret would have to
be distributed to every transmitter and would prove less than a signature does.

Everything therefore rests on verifying before acting. **Nothing touches the
database on the strength of an unverified token**, including to find out who it
is about.

The order:

1. Parse with the algorithm list pinned. No `none`.
2. Refuse a token carrying its own key material (`jwk`, `jku`, `x5u`).
3. `typ` must be `secevent+jwt` — otherwise an ID token from the same issuer is a
   signed object we might act on.
4. `iss` must match the source exactly. A key set that also signs for somebody
   else is not authority to speak as them.
5. `aud` must contain us. A token addressed elsewhere is not ours to act on,
   however valid its signature.
6. Signature against the **source's** keys, fetched from its JWKS.
7. `jti` must be unused.
8. The source must be permitted to send this event type.
9. Only then: resolve the subject, and act.

## What was verified

Fourteen refusals, each breaking exactly one thing and leaving the rest correct:

```
signed with a key we do not trust      typ is not secevent+jwt
issuer does not match the source       audience is somebody else
no jti                                 issued in the future
an event type this source may not send a source configured with no events
several events in one token            a token carrying its own key
not a token at all                     an issuer we have no source for
```

And the whole path, against a real database with a real transmitter signing real
tokens over TLS: **three live sessions, one signed `session-revoked`, zero live
sessions** — with `revocation_reason = shared_signal`, named distinctly from a
logout because they mean very different things to whoever reads the audit trail.

## Replay

A repeated `jti` is **accepted (202) and not acted on twice**. At-least-once
delivery is normal — a transmitter legitimately resends — and answering 4xx would
make it retry forever. The guard is a UNIQUE constraint rather than a prior
SELECT, because two copies arriving at once would both pass a check-then-insert.

The record and the effect commit in **one transaction**: a revocation that
committed without its record could be replayed.

## Subject resolution is a security boundary

How a source names a person decides whose sessions it can end. Matching on email
is the obvious approach and the wrong default — two directories hold the same
address, and a source permitted to speak about its own users would then be able
to end sessions for yours.

| Order | Format | Basis |
|---|---|---|
| 1 | `iss_sub` | The federated identity link the two sides already agreed on |
| 2 | `email` | Only within that source's own organisation |

An unresolvable subject is **not an error** — a transmitter sends events about
people you have never seen. It is recorded, because "forty events about nobody"
is how a misconfigured subject format announces itself.

## A source is scoped

`-events` is required. A source permitted to report device compliance must not
also be able to revoke sessions, and **an empty list allows nothing** — an
unfinished configuration must not read as permission for everything.

## A note on the tests

The embedded-key guard originally had a test that passed for the wrong reason:
the rogue token was also signed by an untrusted key, so it was refused either
way. Mutation testing caught it. The test now asserts *which* check refused it,
so removing the guard fails the test.

## What this implements, and what it does not (August 2026)

Checked against SSF 1.0 Final's own section list rather than against RFC 8417 and
RFC 8935 alone, which is what the review above covers. The framework is larger
than the SET format, and the boundary was nowhere stated.

**Transmitting.** Streams exist — `core.ssf_streams` carries `endpoint_url`,
`events_requested`, `auth_token` and a `status` — and SETs are delivered through
`internal/outbox` with its retry, capped backoff and parked-failure handling.
They are **administered locally**, not through §8.1.1's Stream Configuration
Endpoint. A receiver cannot create, read or update its own stream by HTTP.

**Receiving.** `POST /ssf/receive` accepts SETs from a configured source. We do
not act as a stream-managing receiver: nothing here creates a stream against a
foreign transmitter, reads §7.2 transmitter configuration metadata, or requests
verification.

### The consequence, stated plainly

| SSF 1.0 section | Status |
|---|---|
| §4.1 SET format, explicit typing, `iss`, forbidden `exp`/`sub` | implemented, and reviewed above |
| §6.1.1 Push delivery over HTTP | implemented, both directions |
| §6.1.2 Poll delivery | **not implemented** |
| §7.1 / §7.2 Transmitter configuration metadata | **not implemented** |
| §8.1.1 Stream Configuration Endpoint | **not implemented** — streams are configured by an operator |
| §8.1.4 Verification (the verification event and its `state` echo) | **not implemented** |

So §8.1.4's receiver SHALL — "the Event Receiver SHALL confirm that the value for
`state` is as expected" — does not bind us, because we never request
verification. That is a scope statement rather than an excuse: a deployment that
expects to negotiate a stream with us over the wire, or to verify one, will find
those endpoints absent, and until now nothing here said so.

This is the same rule the rest of this project follows for CIBA (poll mode only,
and discovery says exactly that) and UMA (no claims gathering, so `need_info` is
never returned). An unimplemented half of a framework is only safe when it is
written down; the failure mode otherwise is an integrator discovering it against
a live deployment.
