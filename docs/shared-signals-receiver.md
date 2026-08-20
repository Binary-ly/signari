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


Re-checked August 2026: `Profile.java:177` carries
`SSF("Shared Signals Framework", Type.EXPERIMENTAL)`, and `kc/ssf/` contains
`core`, `services` and `transmitter` — with §8.1.1 stream configuration endpoints
(`SsfAdminResource`, `CreateStreamRequest`, `AddSubjectRequest`).


## Point 3, done properly: every normative clause, against the spec text

The specification was parsed rather than remembered — OpenID Shared Signals
Framework 1.0, Standards Track (Final), **29 August 2025** — and every RFC 2119
keyword extracted with its section. **265 keyword uses across 58 sections; 46
sections carry MUST/SHALL/REQUIRED.**

### The receiver: 12 MUSTs, all implemented, each with the clause beside it

`internal/ssf/receive.go`'s `Verify` was read in full against the extracted text:

| Clause | Requirement | Ours |
|---|---|---|
| §4.1.1 | SETs MUST use explicit typing (RFC 8417 §2.3) | `typ` must equal `secevent+jwt` |
| §4.1.2 | `sub` MUST NOT be present in any SET | refused, with the reason quoted |
| §4.1.3 | the three distinguishing checks together | all three |
| §4.1.6 | `iss` MUST match the stream configuration; receivers MUST validate | `c.Issuer != src.Issuer` → refused |
| §4.1.7 | `exp` MUST NOT be used in SETs | refused |
| §4.1.8 | `aud` | `containsFold(c.Audience, src.Audience)` |
| §3.6 | MUST discard an event with an unprocessable **Critical** subject member | `unprocessableCritical` |

Plus, beyond the profile: algorithms pinned with `none` absent from the list,
`jwk`/`jku`/`x5u` headers refused, exactly one signature required, duplicate JSON
keys refused, `jti` and `iat` required, future-dated tokens refused with a
deliberately asymmetric window.

§4.1.9's `txn` uniqueness and §7.2.4's configuration validation are transmitter
and discovery obligations respectively, not receiver ones; §7.2.4 does not apply
because our sources are operator-configured rather than discovered.

**Conclusion: the receiver holds up.** Every receiver-side MUST in SSF 1.0 Final
is implemented, and the profile's central concern — §4.1.3, "the possibility that
SETs are confused for other kinds of JWTs" — is covered by all three of its
checks rather than the one most implementations stop at.

### The transmitter: we were undiscoverable, and now are not

The same sweep found the gap on the other side. We transmit SETs and published
**no `/.well-known/ssf-configuration` at all**, so §7.1's document did not exist
here. A receiver had no way to learn our issuer, our signing keys or our delivery
method without an operator telling it out of band.

Two details from §7.1 decided the shape:

- **`spec_version` is not optional in effect.** "If absent, the Transmitter is
  assumed to conform to `1_0-ID1` version of the specification" — an implementer's
  draft. Silence is not neutral; it is a claim about a different document. We
  publish `"1_0"`.
- **`jwks_uri` is OPTIONAL in general and required for us:** "MUST be specified
  if the Transmitter intends to generate signed JWTs." Every SET we emit is
  signed.

Implemented in `internal/ssf/metadata.go`, served at `internal/httpapi/ssfmetadata.go`.

**What is deliberately absent, and why absence is the honest answer.** The §8
management endpoints — `configuration_endpoint`, `status_endpoint`,
`add_subject_endpoint`, `remove_subject_endpoint`, `verification_endpoint` — and
`authorization_schemes` are all omitted, because this engine's streams are
administered by its operator. Advertising a configuration endpoint that 404s is
worse than advertising nothing: the receiver's next move is to call it. This is
the rule the project adopted after OIDC discovery once advertised three endpoints
that did not exist.

`default_subjects` is omitted for a sharper reason. §7.1 permits exactly two
values — "If present, the value MUST be either `ALL` or `NONE`" — and this engine
is neither: a stream carries events about the subjects that client has actually
seen, narrower than ALL and wider than NONE. Omitting is explicitly conformant
("If not provided, the Transmitter behavior in this regard is unspecified"),
while `ALL` would promise events about every user in the directory and `NONE`
would direct the receiver to an add-subject endpoint we do not offer.

**The issuer is published verbatim, including a development `http` one.** §7.1
calls for https, but also says the value "MUST be identical to the `iss` claim
value in Security Event Tokens issued from this Transmitter" — and that is the
half a receiver enforces, because §4.1.6 requires it to reject any SET whose
`iss` does not match. Publishing a tidied https variant of an issuer we actually
sign with would satisfy the scheme sentence by breaking the `iss` sentence, and
make us unsubscribable rather than more secure. §7.2 puts the receiver in charge
of noticing: "Receivers SHOULD ensure that the Issuer URL... uses the https
scheme."

**§7.2.1's path case is handled**, which most implementations skip. For an issuer
with a path component the document belongs at
`/.well-known/ssf-configuration/issuer1`, not at the bare path — the rule exists
for multi-tenant hosting, and a transmitter serving only the bare path is
undiscoverable in exactly those deployments. The route is registered only when
the issuer has a path, so the ordinary deployment carries no duplicate.

Tested including a check that follows our **own** advertised `jwks_uri` back
through the router and confirms a key set comes back. A discovery document is
only worth having if following it works, and the failure it prevents — a
plausible path that 404s — is one a receiver otherwise finds at the moment it
tries to verify its first event.


Their SSF tree is `ssf/{core,transmitter,services,tests}`. There is no receiver
package. The two files whose names contain "Receiver" —
`SsfTransmitterGetReceiverClientTest` and `SsfUtilReceiverTest` — are transmitter
tests about the receiver they push *to*. **Our claim to be the only one that
receives holds.**

Not implemented on the transmitter side, for the record:
the section 8 stream management API, RISC events, and an opt-out legacy
Apple SSE CAEP profile.
 The corrected picture is in
[comparison-matrix.md](comparison-matrix.md).

## Second pass: §3 Subject Identifiers, and a wire-format defect (21 August 2026)

The first SSF pass covered §4.1.x — the twelve receiver-side SET validation MUSTs
— and §7.1, the transmitter metadata document. **It never opened §3**, which is
the part that decides *who an event is about*.

### The defect: our events did not carry a top-level `sub_id`

> §3.1: "claim named `sub_id` MUST be used to describe the primary subject of the
> event."
>
> §3.1.1: "MUST include the top-level `sub_id` claim **even for these existing
> event types**." — that is, for CAEP and RISC, which is everything we emit.

`Mint` put the subject **inside the event object**, as `subject`:

```json
{"iss":"...","jti":"...","events":{"...session-revoked":{"subject":{...}}}}
```

That is the pre-1.0 CAEP shape. A receiver written against SSF 1.0 reads the top
level, finds no `sub_id`, and cannot determine which principal the event concerns
— so a session-revoked notice either fails validation or revokes nothing.

**The first pass made this sharper without noticing.** It added
`spec_version: "1_0"` to the transmitter metadata, on the correct reasoning that
omitting the field means a receiver assumes the `1_0-ID1` draft. So this engine
began advertising conformance to Final while continuing to emit draft-shaped
subjects — the two halves of the same specification, disagreeing, because one was
read and the other was not.

Fixed. `sub_id` is now a top-level claim carrying format, `iss` and `sub`.

The event-level `subject` is **kept alongside it**, deliberately: §3.1.2 forbids
it only for *new* event types, and §3.1.1 requires the top-level claim for the
existing CAEP and RISC types without forbidding the old one. Emitting both is
conformant and strictly more interoperable — a 1.0 receiver reads `sub_id`, an
older one reads `subject`, neither is broken by the other. The code carries a note
that if this engine ever defines an event type of its own, §3.1.2 applies and the
line must not be copied.

### The receiver was reading them in the wrong order

`rawSubject` accepted both keys and tried **`subject` first**.

For a well-formed event that is invisible. For an event carrying both, it is a
divergence: we would act on `subject` while a conformant 1.0 receiver acts on
`sub_id`. Two receivers, one signed token, two different principals signed out.

Now `sub_id` first, and an event whose two subjects **disagree** is refused
outright, citing §3.1.4: "Each Subject Member MUST refer to exactly one Subject
Principal." Both keys naming the *same* subject is what we ourselves emit and
stays acceptable.

### Three second passes, six defects, all in unopened sections

| Standard | Section the first pass skipped | Defects |
|---|---|---|
| AuthZEN | §8 Search APIs | 2 |
| OID4VCI | §4 Credential Offer | 2 |
| SSF | §3 Subject Identifiers | 2 |

Not one of the six was in code a first pass read and misjudged. All six were in
code it never reached.

And this one is the sharpest illustration of why that matters: the first pass
fixed the *metadata* claim about which version we implement, without checking
whether the *events* matched it. A section left unopened does not merely stay
unchecked — it can be silently contradicted by the section that was.
