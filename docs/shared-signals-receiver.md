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
