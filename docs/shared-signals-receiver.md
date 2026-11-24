# Receiving Shared Signals

## Introduction

Sometimes another service needs to tell Signari that something happened to a
person. An upstream identity provider may have revoked their session, or disabled
their account. Signari should then end that person's sessions here too.

Signari can be the "receiver" of a Shared Signals Framework
([SSF](glossary.md#shared-signals)) stream. A "transmitter" sends it Security Event
Tokens (SETs): signed JSON Web Tokens ([JWT](glossary.md#jwt)), each describing one
event. One example is a Continuous Access Evaluation Profile
([CAEP](glossary.md#caep)) session revocation. Signari verifies each token before it
acts on it.

You register each transmitter as a "source", with `signari ssf add-source` or
through the Admin API.

## Register a source

A transmitter delivers each SET to this endpoint:

```
POST /ssf/receive
Content-Type: application/secevent+jwt
<the Security Event Token>
```

Register the transmitter as a source, with the event types it may send, then see
what it has sent:

```sh
signari ssf add-source -org <uuid> -name "Upstream IdP" \
  -source-issuer https://idp.example.com \
  -source-jwks https://idp.example.com/oauth2/v1/keys \
  -source-audience https://id.example.com \
  -events https://schemas.openid.net/secevent/caep/event-type/session-revoked

signari ssf received -org <uuid>
```

The Admin API registers sources the same way, at
`/admin/organizations/{orgID}/ssf-sources`. See the [Admin API
reference](admin-api.md).

## Receiving is the harder half

**Transmitting** is the simpler half of Shared Signals: "a session was revoked
here, tell the applications". Receiving means acting on another service's word
about your own people, so everything on this page is about checking that word
before acting on it.

## Conformance review against RFC 8417 and RFC 8935, August 2026

This section is the record of a review, kept as it was written. It was made against
the **RFC texts**, not summaries. Four defects, two of them MUSTs:

| Finding | Where | Status |
|---|---|---|
| **Errors answered `401`.** RFC 8935 §2.3: *"When the SET Recipient detects an error parsing, validating, or authenticating a SET ... SHALL respond with an HTTP Response Status Code of 400"* | 8935 §2.3 | **fixed** |
| **No `Content-Language` header.** §2.3 says the error response **MUST** include one | 8935 §2.3 | **fixed** |
| **`exp` was ignored.** RFC 8417 §2.2: it is *"the time after which the JWT MUST NOT be accepted for processing"*. NOT RECOMMENDED in a SET, but not advisory when present — a deliberately time-boxed event was being acted on afterwards | 8417 §2.2 | **fixed** |
| **Multiple event entries were refused outright.** §2.2 forbids expressing multiple *independent* logical events; it permits several entries describing **one** event, which is how CAEP profiles convey detail. We were rejecting conforming transmitters | 8417 §2.2 | **fixed** |
| Unregistered error code `internal_error` | 8935 §2.4 | **fixed** |

### On the error-code decision

The `401`-with-a-uniform-body choice was deliberate. It avoided telling an
unauthenticated caller which issuers we are configured for. The RFC prescribes `400`
with **registered codes** that distinguish `invalid_issuer` from `invalid_audience`
from `invalid_key`.

We now follow the RFC. A partner whose transmitter is misconfigured has to be able to
tell *which* thing we rejected. The residual disclosure, "this deployment has a
source for issuer X", requires guessing an exact issuer URL to learn. Interop and
debuggability win that trade. The reasoning is recorded here so the decision can be
revisited rather than rediscovered.

### On multiple entries

The original concern, "partially applying a token leaves a state nobody can reason
about", was right, and the remedy was wrong. Refusing rejected conforming
transmitters.

Every entry is now applied **inside the one transaction**, which is what actually
makes partial application impossible. Every entry must also be permitted: a source
allowed to report one thing must not smuggle another alongside it.

## The endpoint is unauthenticated, and that is correct

A transmitter pushes without credentials: **the signature is the credential**. That
is RFC 8935's model, and it is the right one. A shared secret would have to be
distributed to every transmitter, and would prove less than a signature does.

Everything therefore rests on verifying before acting. **Nothing touches the
database on the strength of an unverified token**, including to find out who it is
about.

The order:

0. Choose the source by the token's `iss` **and** `aud`, read unverified. That
   only selects whose keys to verify against; every check below is made again
   against what it selects.
1. Parse with the algorithm list pinned. No `none`.
2. Refuse a token carrying its own key material (`jwk`, `jku`, `x5u`).
3. `typ` must be `secevent+jwt` — otherwise an ID token from the same issuer is a
   signed object we might act on.
4. `iss` must match the source exactly. A key set that also signs for somebody
   else is not authority to speak as them.
5. `aud` must contain us. A token addressed elsewhere is not ours to act on,
   however valid its signature.
6. Signature against the **source's** keys, fetched from its JSON Web Key Set
   ([JWKS](glossary.md#jwks)).
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

And the whole path was run against a real database, with a real transmitter signing
real tokens over Transport Layer Security ([TLS](glossary.md#tls)): **three live
sessions, one signed `session-revoked`, zero live sessions**. The sessions ended
with `revocation_reason = shared_signal`. That is named distinctly from a sign-out,
because the two mean very different things to whoever reads the audit trail.

## Two organisations, one transmitter

A shared upstream sends every customer's events under one issuer, and tells them
apart by audience. So two organisations here can each have a source for the same
`iss`.

The source is therefore chosen by the **issuer and the audience together**, and that
pair belongs to one organisation in the whole deployment. `ssf add-source` refuses a
second organisation's registration of it, compared without regard to case, as the
audience check is.

| The token | Answer |
|---|---|
| `iss` and `aud` match one source | verified against that source, and the subject is resolved in its organisation only |
| `aud` lists several audiences that reach two organisations' sources | `400 invalid_audience`, and nothing is acted on. An event addressed to two organisations names nobody in particular |
| `aud` names a recipient here that does not accept this `iss` | `400 invalid_issuer`, RFC 8935 §2.4's "the SET Issuer is invalid for the SET Recipient" |
| `aud` names no recipient here | `400 invalid_audience`, "the SET Audience does not correspond to the SET Recipient" |

Until October 2026 the source was found by issuer alone, and whichever
organisation's row the database returned answered for both. The other
organisation's events were refused for their audience, so it received nothing.

Had the two shared an audience, its events would have verified, and been resolved in
the first organisation's directory. That would have signed out somebody else's
people. The upgrade migration refuses to run while two organisations hold one pair,
and names them, because which of them keeps it is the administrator's decision.

## Replay

A repeated `jti` is **accepted (202) and not acted on twice**. At-least-once delivery
is normal, because a transmitter legitimately resends, and answering 4xx would make
it retry forever.

The guard is a UNIQUE constraint rather than a prior SELECT. Two copies arriving at
once would both pass a check-then-insert.

The record and the effect commit in **one transaction**: a revocation that committed
without its record could be replayed.

## Subject resolution is a security boundary

How a source names a person decides whose sessions it can end. Matching on email is
the obvious approach, and the wrong default. Two directories can hold the same
address. A source permitted to speak about its own people would then be able to end
sessions for yours.

| Order | Format | Basis |
|---|---|---|
| 1 | `iss_sub` | The federated identity link the two sides already agreed on |
| 2 | `email` | Only within that source's own organisation |

An unresolvable subject is **not an error**, because a transmitter sends events about
people you have never seen. It is recorded, because "forty events about nobody" is
how a misconfigured subject format announces itself.

## A source is scoped

`-events` is required. A source permitted to report device compliance must not also
be able to revoke sessions. And **an empty list allows nothing**: an unfinished
configuration must not read as permission for everything.

## A note on the tests

The embedded-key guard originally had a test that passed for the wrong reason. The
rogue token was also signed by an untrusted key, so it was refused either way.
Mutation testing caught it. The test now asserts *which* check refused it, so
removing the guard fails the test.

## What this implements, and what it does not (August 2026)

This was checked against SSF 1.0 Final's own section list. The review above covers
only RFC 8417 and RFC 8935. The framework is
larger than the SET format, and the boundary was nowhere stated.

**Transmitting.** Streams exist: `core.ssf_streams` carries `endpoint_url`,
`events_requested`, `auth_token` and a `status`. SETs are delivered through
`internal/outbox`, with its retry, capped backoff and parked-failure handling. A
stream is **created by an administrator**, with `signari ssf add-stream` or the
Admin API. Through §8.1.1's Stream Configuration Endpoint, `/ssf/stream`, a
receiver can read its own stream and change what it asks for, and a request to
create or delete one is answered `403`. It can also ask for a verification event
at `POST /ssf/verify`. See [what a receiver can do with its
stream](ssf-caep.md#what-a-receiver-can-do-with-its-stream).

**Receiving.** `POST /ssf/receive` accepts SETs from a configured source. We do not
act as a stream-managing receiver. Nothing here creates a stream against a foreign
transmitter, reads §7.2 transmitter configuration metadata, or requests
verification.

### The consequence, stated plainly

| SSF 1.0 section | Status |
|---|---|
| §4.1 SET format, explicit typing, `iss`, forbidden `exp`/`sub` | implemented, and reviewed above |
| §6.1.1 Push delivery over HTTP | implemented, both directions |
| §6.1.2 Poll delivery | implemented **as transmitter** (`POST /ssf/poll`); this receiver does not pull from an upstream queue |
| §7.1 / §7.2 Transmitter configuration metadata | implemented — served at `/.well-known/ssf-configuration` |
| §8.1.1 Stream Configuration Endpoint | implemented **as transmitter**, for reading and changing a stream (`GET`, `PATCH` and `PUT /ssf/stream`); creating and deleting one is `403`, because streams are created by an administrator. This receiver does not call another transmitter's endpoint |
| §8.1.4 Verification (the verification event and its `state` echo) | implemented **as transmitter** (`POST /ssf/verify`); this receiver never requests verification |

So §8.1.4's receiver SHALL, "the Event Receiver SHALL confirm that the value for
`state` is as expected", does not bind us, because we never request verification.

That is a scope statement rather than an excuse. A deployment that expects to
create a stream with us over the wire is refused, because an administrator creates
it. Until now nothing here said so.

This is the same rule the rest of this project follows: advertise exactly what is
built, and say plainly what is not. User-Managed Access ([UMA](glossary.md#uma))
does it too: there is no claims gathering, so `need_info` is never returned.

An unimplemented half of a framework is only safe when it is written down. The
failure mode otherwise is an integrator discovering it against a live deployment.

The converse failure is as real, and this page had it. A table still said "not
implemented" for two sections that had since been built, which costs a reader a
capability they already have.

## Every normative clause, against the spec text

The specification was parsed rather than remembered: OpenID Shared Signals Framework
1.0, Standards Track (Final), **29 August 2025**. Every RFC 2119 keyword was
extracted with its section. **265 keyword uses across 58 sections; 46 sections
carry MUST/SHALL/REQUIRED.**

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

Beyond the profile, there is more:

- algorithms pinned, with `none` absent from the list;
- `jwk`/`jku`/`x5u` headers refused;
- exactly one signature required;
- duplicate JSON keys refused;
- `jti` and `iat` required;
- future-dated tokens refused, with a deliberately asymmetric window.

§4.1.9's `txn` uniqueness is a transmitter obligation, not a receiver one, and
§7.2.4's configuration validation is a discovery obligation. §7.2.4 does not apply
because our sources are configured by an administrator, rather than discovered.

**Conclusion: the receiver holds up.** Every receiver-side MUST in SSF 1.0 Final is
implemented. The profile's central concern, §4.1.3, "the possibility that SETs are
confused for other kinds of JWTs", is covered by all three of its checks.

### The transmitter: we were undiscoverable, and now are not

The same sweep found the gap on the other side. We transmit SETs, and published
**no `/.well-known/ssf-configuration` at all**, so §7.1's document did not exist
here. A receiver had no way to learn our issuer, our signing keys or our delivery
method without an administrator telling it out of band.

Two details from §7.1 decided the shape:

- **`spec_version` is not optional in effect.** "If absent, the Transmitter is
  assumed to conform to `1_0-ID1` version of the specification" — an implementer's
  draft. Silence is not neutral; it is a claim about a different document. We
  publish `"1_0"`.
- **`jwks_uri` is OPTIONAL in general and required for us:** "MUST be specified
  if the Transmitter intends to generate signed JWTs." Every SET we emit is
  signed.

Implemented in `internal/ssf/metadata.go`, served at `internal/httpapi/ssfmetadata.go`.

**What was absent, and why absence was the honest answer.** When this was written,
the §8 management endpoints were omitted: `configuration_endpoint`,
`status_endpoint`, `add_subject_endpoint` and `remove_subject_endpoint`. They did
not exist yet. `verification_endpoint` came first, since it changes nothing about a
stream ([asking whether a stream works](ssf-caep.md#asking-whether-a-stream-works)).
All five are advertised now that each one works. A receiver can read and change its
own stream through them, but not create or delete one.

`authorization_schemes` is still omitted. A receiver authenticates to these
endpoints as its stream's client, with HTTP Basic or a certificate, and neither is
the access token that §7.1.1's OAuth example describes.

Advertising a configuration endpoint that 404s is worse than advertising nothing:
the receiver's next move is to call it. This is the rule the project adopted after
OpenID Connect ([OIDC](glossary.md#oidc)) discovery once advertised three endpoints
that did not exist.

`default_subjects` is omitted for a sharper reason. §7.1 permits exactly two values,
"If present, the value MUST be either `ALL` or `NONE`", and this engine is neither.
A stream carries events about the subjects that client has actually seen, narrower
than ALL and wider than NONE.

Omitting is explicitly conformant ("If not provided, the Transmitter behavior in this
regard is unspecified"). `ALL` would promise events about every person in the
directory. `NONE` would tell the receiver it hears about nobody until it adds them,
and adding a person its client has not met opens nothing here.

**The issuer is published verbatim, including a development `http` one.** §7.1 calls
for https. But it also says the value "MUST be identical to the `iss` claim value in
Security Event Tokens issued from this Transmitter". That is the half a receiver
enforces, because §4.1.6 requires it to reject any SET whose `iss` does not match.

Publishing a tidied https variant of an issuer we actually sign with would satisfy
the scheme sentence by breaking the `iss` sentence. It would make us unsubscribable,
rather than more secure. §7.2 puts the receiver in charge of noticing: "Receivers
SHOULD ensure that the Issuer URL... uses the https scheme."

**§7.2.1's path case is handled.** For an issuer
with a path component, the document belongs at
`/.well-known/ssf-configuration/issuer1`, not at the bare path. The rule exists for
hosting many organisations on one host. A transmitter serving only the bare path is
undiscoverable in exactly those deployments. The route is registered only when the
issuer has a path, so the ordinary deployment carries no duplicate.

The tests include a check that follows our **own** advertised `jwks_uri` back
through the router, and confirms a key set comes back. A discovery document is only
worth having if following it works. The failure it prevents, a plausible path that
404s, is one a receiver otherwise finds at the moment it tries to verify its first
event.


### What this receiver does not do yet

Stated here so the gaps are visible rather than discovered:

- **Calling a transmitter's §8 stream management API**, to create, update or
  delete a stream over HTTP. A source here is registered by an administrator
  instead. As a transmitter, Signari lets a receiver read and change its own
  stream, but not create one: that is a deliberate choice about who may subscribe
  to events. See [Shared Signals and CAEP](ssf-caep.md).
- **The legacy Apple SSE CAEP profile**, which predates the final specification.
- **RISC's other events**, such as `identifier-changed` and the recovery family.
  They are recorded with `no handler` rather than acted on.

## What an account event does

A source has to list each of these in `-events` before it is believed. They come
from Risk Incident Sharing and Coordination (RISC), a companion set of events to
CAEP:

| Event | Here |
|---|---|
| `risc/event-type/account-disabled`, `account-purged` | The person's sessions end. The account stays: it is this organisation's to close, and a transmitter's word on one identity is not a verdict on all of them. |
| `risc/event-type/account-credential-change-required`, `credential-compromise` | The sessions end and the next sign-in with a password here is held until it is changed, because the password that leaked may be this one. A federated person with no password here is signed out only. |
| `risc/event-type/account-enabled` | Recorded. A session that ended stays ended. |

## Pulling events from a transmitter

Some transmitters only offer a queue, and a receiver behind a firewall cannot be
pushed to at all. So a source can be polled, by RFC 8936, instead of or as well as
accepting pushes:

```sh
signari ssf add-source -org <uuid> -name Upstream -source-issuer https://idp.example.com \
  -source-jwks https://idp.example.com/jwks -source-audience https://id.example.com \
  -events https://schemas.openid.net/secevent/caep/event-type/session-revoked
signari ssf poll-source -org <uuid> -source-issuer https://idp.example.com \
  -url https://idp.example.com/ssf/poll -client-id our-client < credential-file
```

Every thirty seconds, one node takes the source and asks for what is queued. The
token is verified and acted on exactly as a pushed one is. Then:

- What was acted on is acknowledged in the next request. So a node that stops
  between the two is sent it again, and the replay guard answers that.
- What was refused is reported in `setErrs`, so it does not come back.
- What could not be judged stays queued. When the source's keys cannot be fetched,
  the token has told us nothing, and calling it invalid would lose it. A pushed
  token in that state is answered 500 for the same reason.

A polled token must carry the issuer of the source that was polled. One
transmitter's credential buys no say over another's people, whichever keys verify.

`signari ssf received` starts with how the last turn went. The Admin API has the same
in `last_polled_at` and `last_poll_error`.

Pulled with a `-client-id`, the credential goes as HTTP Basic, which is what this
engine's own `POST /ssf/poll` wants. With none, it is a bearer token.
`signari ssf poll-source -remove` stops and forgets it. Disabling a source stops its
turns too.

## Second pass: §3 Subject Identifiers, and a wire-format defect (21 August 2026)

The first SSF pass covered §4.1.x, the twelve receiver-side SET validation MUSTs, and
§7.1, the transmitter metadata document. **It never opened §3**, which is the part
that decides *who an event is about*.

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
level, finds no `sub_id`, and cannot determine which principal the event concerns.
So a session-revoked notice either fails validation, or revokes nothing.

**The first pass made this sharper without noticing.** It added
`spec_version: "1_0"` to the transmitter metadata. Its reasoning was correct:
omitting the field means a receiver assumes the `1_0-ID1` draft. So this engine began
advertising conformance to Final, while continuing to emit draft-shaped subjects.
The two halves of the same specification disagreed, because one was read and the
other was not.

Fixed. `sub_id` is now a top-level claim carrying format, `iss` and `sub`.

The event-level `subject` is **kept alongside it**, deliberately. Section 3.1.2
forbids it only for *new* event types. Section 3.1.1 requires the top-level claim for the existing CAEP
and RISC types, without forbidding the old one.

Emitting both is conformant, and strictly more interoperable. A 1.0 receiver reads
`sub_id`, an older one reads `subject`, and neither is broken by the other. The code
carries a note: if this engine ever defines an event type of its own, §3.1.2 applies,
and the line must not be copied.

### The receiver was reading them in the wrong order

`rawSubject` accepted both keys, and tried **`subject` first**.

For a well-formed event that is invisible. For an event carrying both, it is a
divergence: we would act on `subject` while a conformant 1.0 receiver acts on
`sub_id`. Two receivers, one signed token, two different principals signed out.

Now `sub_id` comes first, and an event whose two subjects **disagree** is refused
outright, citing §3.1.4: "Each Subject Member MUST refer to exactly one Subject
Principal." Both keys naming the *same* subject is what we ourselves emit, and stays
acceptable.

### Three second passes, six defects, all in unopened sections

The standards in this table include OpenID for Verifiable Credential Issuance
([OID4VCI](glossary.md#oid4vci)):

| Standard | Section the first pass skipped | Defects |
|---|---|---|
| AuthZEN | §8 Search APIs | 2 |
| OID4VCI | §4 Credential Offer | 2 |
| SSF | §3 Subject Identifiers | 2 |

Not one of the six was in code a first pass read and misjudged. All six were in code
it never reached.

And this one is the sharpest illustration of why that matters. The first pass fixed
the *metadata* claim about which version we implement, without checking whether the
*events* matched it. A section left unopened does not merely stay unchecked. It can
be silently contradicted by the section that was.

## The subject the receiver could not see (21 August 2026)

This was found by the same sweep that produced the Lightweight Directory Access
Protocol ([LDAP](glossary.md#ldap)) and Chrome-posture findings. That sweep looked
for fields decoded off the wire and read by nothing. `setClaims.SubID` was one.

SSF 1.0 puts the subject at the **top level** of the SET:

> §3.1 — "claim named `sub_id` MUST be used to describe the primary subject of
> the event."
>
> §3.1.1 — "MUST include the top-level `sub_id` claim even for these existing
> event types" — that is, for CAEP and RISC events, which is all of the ones
> anybody sends.

Our **transmitter** was fixed for this in an earlier pass. Its comment records the
reason precisely. The subject used to travel inside the event object, in the pre-1.0
CAEP shape. So *"a conformant SSF 1.0 receiver reading the top level found nothing
and could not tell who the event was about."*

**Our receiver was that receiver.** It read `c.Events[type]` and nothing else.
`subjectFrom` looked for `sub_id` or `subject` inside the event body. The top-level
claim was decoded into `c.SubID`, and used by no code at all.

So a conformant SSF 1.0 transmitter, including Signari talking to itself, could send
a `session-revoked` event that **verified perfectly and named nobody**. The signature
was valid, the issuer and audience matched, `jti` was present, `iat` was sane, and
`exp` and `sub` were correctly absent. Every check this subsystem performs said yes,
and the resulting `Subject` was the zero value.

Nothing was refused, and nothing was revoked. The failure mode is a session that
stays alive after a transmitter said to kill it, reported as success. That is the
single outcome the whole receiver exists to prevent. It is also the only one that
leaves no trace anywhere to notice it by.

### What was done

**The event body still wins when it carries a subject**, because a transmitter
using the pre-1.0 in-event shape puts it there. And `subjectFrom` already makes the argument
about `sub_id` versus `subject`: *"a receiver that only understands one silently
ignores half the transmitters in the world."* Preferring the top level would have
moved the blind spot, rather than removed it.

**A top-level subject that contradicts the event's own is refused.** §3.1.4, "Each
Subject Member MUST refer to exactly one Subject Principal", was already enforced
*within* an event, between `sub_id` and `subject`. Reading the top level opens a
second door to the same contradiction.

A receiver that enforces a rule at one door and not the other has not enforced it.
Which subject a receiver honours would otherwise decide who gets signed out.

### A second defect, older than this one

The member-by-member comparison was extracted into `subjectsDiffer`, and given a test
it did not have. A mutation that compared **only `sub`**, ignoring `iss`, survived
every pre-existing test.

That is not cosmetic. `iss_sub` is *issuer-scoped*: `user-42` at `transmitter.test`
and `user-42` at `evil.test` are different people. A comparison blind to `iss` reads
them as the same principal.

So a transmitter could name its own person in the event body, and somebody else's at
the top level. The pair would be accepted as consistent. The within-event check had
the same blind spot for as long as it has existed.

### Mutation results

The mutation pass caught three changes, and found one equivalent:

```
CAUGHT      ignore the top-level sub_id (the state before this pass)
CAUGHT      skip the cross-level contradiction check
CAUGHT      compare only `sub`, ignoring `iss` (the older defect)
EQUIVALENT  make the top level win over the event body
```

The last is worth stating rather than fixing. Precedence between the two is
**unobservable whenever both are present**, because disagreement is refused, and
agreement makes the choice moot.

A test asserting precedence would be asserting an implementation detail that no
conformant input can distinguish. The honest record is that the contradiction check
is what makes precedence not matter.

## Reading the sections nobody had opened (21 August 2026)

Six second passes had already led to one conclusion: **"the risk is unread
sections, not misread ones"**. Every finding came from a section a
first pass never opened, and none from code a first pass read and misjudged.

That is a claim you can act on mechanically, rather than by re-reading everything.
List the specification's sections, list the ones our code and docs cite, and look at
the difference.

For SSF 1.0 that is **77 sections, 33 cited, 49 never referenced anywhere**. Two of
the 49 mattered.

### §3.3 Complex Subject Members — a second silent no-op

A Complex Subject carries `"format": "complex"`, and its identity one level down, in
Simple Subject Members named `user`, `device`, `session`, `tenant` and so on. The
specification's own example:

```json
"sub_id": {
  "format": "complex",
  "user":   {"format": "email",   "email": "bar@example.com"},
  "tenant": {"format": "iss_sub", "iss": "https://example.com/idp1", "sub": "1234"}
}
```

`subjectFrom` read `format`, `iss`, `sub` and `email` off the object directly.
Against this, all four are absent. So it returned an empty Subject with
`Format: "complex"`, and `ResolveSSFSubject` had no case for that format. The event
was recorded `no_matching_user`, while revoking nothing.

**This is the same failure as the top-level `sub_id` defect above, through a
different door**. Finding it one day later is the argument for the sweep. The first
fix was correct, and did not generalise. The bug was never really "we read the wrong
level". It was "we assume one subject shape".

Reading the `user` member is not a choice among candidates. §3.3.1: *"All members
within a Complex Subject MUST represent attributes of the same Subject Principal.
As a whole, the Complex Subject MUST refer to exactly one Subject Principal."*
They are attributes of one principal, and `user` is the one naming an account.

**Falling back to `device` or `tenant` when `user` is absent is refused**, and
tested. A device identifier that happens to collide with an account's identifier
would otherwise revoke a real person's sessions.

#### Why reading only `user` is safe, and where that safety actually lives

This receiver revokes per person, so an event scoped to one session is applied more
broadly than it was sent. The specification already has the mechanism for that, and
we already implement it. Section 3.6 requires a receiver to **discard** an event carrying a
Critical member it cannot process.

`device`, `session`, `tenant` and the rest are deliberately **absent** from
`processableSubjectMembers`. So a transmitter that cannot accept the wider
application marks the member Critical, and the event is refused instead of
over-applied.

That dependency is now a test, rather than an implication. Consider the mutation that
adds every complex member name to `processableSubjectMembers`, which looks like
completing the list. It kills the valve, and fails both that test and a pre-existing
one.

### §9.3 Malicious Subject Removal — correct already, and now held

> "Event Receivers MUST tolerate receiving events for subjects that have been
> removed from the stream, and MUST NOT report these events as errors to the
> Event Transmitter."

The reason is in the section's title. Removing a subject from a stream is something
an **attacker** wants, because it blinds the receiver to that account while they use
it. A transmitter may therefore keep sending events for a removed subject. A receiver
that answers 4xx teaches it to stop, finishing the attacker's work on their behalf.

We were already correct: an unresolvable subject is recorded as `no_matching_user`,
committed, and answered 202. Nothing held it there. The tempting cleanup is to treat
an event about nobody as a client error, because from the inside that is exactly what
it looks like. There is now a test, and the mutation that returns 400 fails it.

### §9.1 Subject Probing — not applicable, checked rather than assumed

Its receiver-facing MUST NOT concerns what a receiver may infer from a 204 to an *add
subject* request. We never call one: `add_subject_endpoint` appears in this codebase
only as an endpoint Signari serves as a transmitter.

The mutation pass for these sections caught all four changes:

```
CAUGHT   ignore complex subjects (the state before this pass)
CAUGHT   fall back to device/session/tenant when `user` is absent
CAUGHT   mark every complex member processable (drops the §3.6 valve)
CAUGHT   answer 400 for an event about a subject we cannot resolve
```

## Re-review against the Shared Signals Framework, August 2026

Signari's Shared Signals receiver accepts Security
Event Tokens (SETs) from another service. A SET is a signed [JSON Web Token
(JWT)](glossary.md#jwt) that describes one security event. This section is the
record of a review of that receiver, kept as it was written.

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
exactly that. It then honoured the claim when present, refusing a SET whose expiry
had passed. That was a deliberate earlier fix, and the comment recorded why. A
transmitter that deliberately time-boxed an event had found us acting on it
afterwards.

Reasonable, and aimed at the wrong thing. **`exp` is not there to time-box an
event. It is forbidden so that a SET cannot be shaped like an ID token.** Once
that is the reason, honouring the claim is not enough. A SET with a comfortable
future expiry is exactly as confusable as an expired one, and ours accepted it.

**§4.1.2 — a top-level `sub` is forbidden, and we never checked.**

> The JWT "sub" claim MUST NOT be present in any SET containing an SSF event.

It sits under §4.1.3, *"Distinguishing SETs from other Kinds of JWTs"*. That
section opens: *"Of particular concern is the possibility that SETs are confused
for other kinds of JWTs."* An SSF event names its subject in `sub_id`. A top-level `sub` is the shape
of an ID token.

We check `typ: secevent+jwt`, which is the primary confusion defence, and which
would already refuse an actual ID token. The profile adds these two because typ
checking is not universal. Defence in depth is its stated purpose, and we had
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

An implementation of a profiled specification has two documents to satisfy. The
profile is the one that adds restrictions the base RFC calls optional. Citing the
base RFC in a comment, as ours did, accurately, is what made the gap look like
diligence.

## Adversarial re-review, August 2026

This was the third pass over the receiver. It was made against the **Shared Signals
Framework 1.0 Final** text, pulled fresh rather than recalled. It used hostile input,
rather than one-field-wrong variations.

Why this surface and not another: accepting one forged Security Event Token
terminates a named person's sessions. Anybody who gets a SET past this code has a
repeatable denial of service against any person in the organisation.

### A real defect: `aud` may be a single string

§4.1.8, verbatim:

> The "aud" claim can be a single string or an array of strings.

RFC 7519 §4.1.3 says the same for every JSON Web Token ([JWT](glossary.md#jwt)).
And **three of the Shared Signals specification's own example SETs use the string
form**: Figures 8, 9 and 10 all carry `"aud": "636C69656E745F6964"`.

We parsed it as `[]string` only. The consequence is worse than a failed audience
check. Go's `encoding/json` reports a type mismatch, so the **whole claim set** fails
to unmarshal, and the receiver answers `malformed claims`. An administrator
connecting a conformant transmitter is told their token is malformed, with nothing
pointing at the audience, while every event is silently dropped.

Fixed with a custom unmarshaller that accepts both forms, and the string form is
still *checked*. `TestAStringAudienceNamingSomebodyElseIsStillRefused` exists so the
fix cannot become "accept any string".

This is the same defect class this review has hit before: **the base RFC and the
profile were both consulted, and the permissive half of the base RFC was
overlooked**. That happened because the profile's own examples were not read as
test vectors.

### What the hostile inputs found

| Attack | Result |
|---|---|
| `alg: none` | refused |
| HS256 signed with the transmitter's **public key** as the secret | refused |
| A *configured* transmitter signing in another configured transmitter's name | refused |
| Two signatures, one legitimate and one attacker's, over one payload | refused |
| Payload that is `"a string"`, `[1,2,3]`, `null`, or truncated | refused |
| `aud` array listing us among several | accepted (§4.1.8) |
| Unknown top-level claims and unknown event-object fields | ignored (§4.2.3) |

The last two matter as much as the refusals. Section 4.2.3 makes ignoring unknown
fields a **MUST**. It sits directly beside the rule that an unknown event *type* is
refused. That pair is often conflated into "reject anything unfamiliar", which would
make every transmitter extension a breaking change.

### Which defences are actually load-bearing

Mutation testing answered a question reading could not. Of four guards in the
verification path, **two are inherited from go-jose rather than enforced by us.**

| Guard | Removing it breaks a test? |
|---|---|
| `iss` pinned to the source configuration | **yes** |
| `jwk` / `jku` / `x5u` self-supplied keys refused | **yes** |
| Explicit algorithm allow-list excluding HS256 | **no** — go-jose refuses an HS256 signature against an ECDSA key on type grounds |
| Exactly one signature | **no** — `JSONWebSignature.Verify` declines a multi-signature object and requires `VerifyMulti` |

Both survivors were investigated rather than assumed. Neither is a hole: the attacks
are refused either way, verified by actually mounting them. But the comments in the
test file now say **which** check fires. Two of the tests originally implied our
guard was doing work that the library was doing.

That distinction is not pedantry. A JOSE library change, or a future need for
`VerifyMulti`, would make our guards the only thing standing. And nothing in the
suite would have told us they had been decorative all along. This is the same failure
this project has already found twice in its own comments. Finding it a third time in
a *test* is the reason the mutation pass exists.

## MUST-by-MUST sweep, August 2026: `critical_subject_members`

This review used the method that found three unmet requirements in OpenID for
Verifiable Credential Issuance ([OID4VCI](glossary.md#oid4vci)). The method extracts
every `MUST` from the specification text, and checks each one against the code. It
was applied to Shared Signals Framework 1.0 (29 August 2025, the current Final).

94 `MUST` sentences; 49 of them touch streams, subjects or delivery. One was unmet,
and the receiver contained no mention of it at all.

### §3.6 Receiver Subject Processing

> "An SSF Receiver MUST make a best effort to process all members from a Subject
> in an SSF event. The Transmitter Configuration Metadata (Section 7.1) defined
> below MAY define certain members within a Complex Subject to be Critical. **An
> SSF Receiver MUST discard any event that contains a Subject with a Critical
> member that it is unable to process.**"

and §7.1's metadata entry:

> `critical_subject_members` — "An array of member names in a Complex Subject
> which, if present in a Subject Member in an event, MUST be interpreted by a
> Receiver."

We implemented neither. The receiver reads `format`, `iss`, `sub` and `email`, and
silently ignored everything else.

### Why this is a scope defect, not an authenticity one

Every other check in this receiver asks *is this event genuine*: signature, issuer,
audience, `jti`, `iat`, allowed event types. This one asks a different question:
**do I understand what the event is about?**

A transmitter marking a `device` member Critical is saying the event concerns one
device, rather than the whole account. Ignoring that member does not fail. It
applies the right action to the wrong set of things. A session-revocation scoped to
one laptop gets applied to every session the person has, and nothing anywhere reports
that the blast radius was wrong.

That is the same silent-widening shape as the token-lifecycle defects found earlier
in this codebase, arriving from a completely different direction. The common
property is a constraint that was communicated, and then not consulted.

### The implementation

`critical_subject_members` is stored per source, not fetched live from the
transmitter's metadata document. That is the same decision as `allowed_events`, for
the same reason. What this receiver will act on is a local decision. Letting a remote
document widen or narrow it at request time makes the security posture depend on
somebody else's uptime and honesty.

The check runs on the **raw** subject object rather than the parsed `Subject`. The
entire point is to notice members we do not model, and a parsed struct has already
discarded them.

`processableSubjectMembers` sits directly beside `subjectFrom`, since §3.6 turns on
"unable to process". A member added to the parser without being added to that set
would make us discard events we now understand perfectly well.

### Mutation results

The mutation pass caught three changes, and one survived:

```
CAUGHT   critical members never checked
CAUGHT   absent critical member still discards
CAUGHT   members we can process still discard
SURVIVED check fires with nothing declared
```

The survivor was an early return for the empty case, and it was genuinely redundant,
not merely hard to test. Ranging over an empty slice already does nothing, and
indexing a nil map already reports "not present". It was **deleted** rather than kept
and labelled.

That is worth distinguishing from the diagnostic-only branches elsewhere in this
codebase, which survive mutation but earn their place by producing a better error
message. This one produced nothing at all. A short-circuit that only restates what the
loop does is weight without meaning.

### The rest of the sweep

The other 93 `MUST` sentences were checked, and are met. That includes the ones most
often skipped. These are explicit `typ` of `secevent+jwt` (§4.1.1), `iss` matching
the stream configuration (§4.1), audience checking, and refusing a SET with no
`jti`. Without
that last one there is no replay guard at all.

## Re-verified against current SSF 1.0 — 24 August 2026

A deep pass on Shared Signals, the highest-consequence subsystem here. The worst
defect ever found in this codebase lived in it: a `session-revoked` SET that verified
perfectly and named nobody. `internal/ssf/receive.go` was re-read against SSF 1.0
Final (29 August 2025, current).

### All three subject shapes are read

The specification allows a subject to arrive three ways. A receiver that handles only
one silently ignores events about people it should be acting on.

- **Top-level `sub_id`** (§3.1). Reading only the inside of the event object was the
  defect above. A conformant transmitter putting the subject at the top level had
  every event accepted and applied to nobody. Fixed in `beedd83`/`bbe776c`.
- **Complex subjects** (§3.3), resolved through the `user` member.
- **`iss_sub`**, compared issuer-scoped. So `user-42` at `transmitter.test` and
  `user-42` at `evil.test` are two different principals, not one.

Verified by decoding real transmitted tokens, not only fixtures of our own making. A
receiver tested solely against its own encoder agrees with itself about a wire format
both halves may be reading wrongly.

### Receiver rules re-verified against the current spec text

- §4.1.2 `sub` MUST NOT be present, §4.1.7 `exp` MUST NOT — both refused, both for
  the stated defence-in-depth against JWT confusion (a SET carrying `sub`+`exp` is
  shaped like an ID token).
- §3.1.4 a subject MUST refer to exactly one principal — refused both within an
  event and across the top-level `sub_id`-vs-event-`subject` levels.
- §3.6 a Critical member the receiver cannot interpret → discard rather than act
  on a scope we are ignoring.
- Per-type source authorization: a source allowed one event type may not smuggle
  another alongside it.

**Verdict:** no new defect. The subsystem where the worst defect was found now reads
all three subject shapes the specification defines. Every receiver-side MUST has been
re-verified against the current SSF 1.0 text.
