# Shared Signals and CAEP

Continuous Access Evaluation: relying parties subscribe to a stream of security
events about subjects they have seen, and react as they arrive.

## The argument

An access token is valid until it expires. That is the whole security model of a
bearer token, and it means a relying party keeps honouring one for its full
lifetime after the session behind it was revoked, the password was changed, or
the account was disabled. Short lifetimes narrow that window; they do not close
it, and shortening them costs a token request every few minutes per user.

CAEP closes it by **telling** the relying party. When a session is revoked here,
every receiver that has seen that subject learns within seconds.

This project has made the same argument about logout from the start — that a
logout nobody can prove happened is not a logout. CAEP is that argument applied
continuously instead of once.


## Registering a receiver

```sh
signari ssf add-stream -org <org-uuid> -client-id <client> \
  -endpoint https://receiver.example.com/events \
  -receiver-token "<bearer token the receiver issued us>"

signari ssf list
```

There was no way to do this until recently: a stream could only be created by
hand-written SQL, which is how it was first tested. A feature nobody can
configure is one nobody uses.

## The token that was never sent

`ssf_streams.auth_token` existed from the first migration, with a comment saying
it "authenticates US to THEM" — and **nothing ever sent it**. RFC 8935 push
delivery expects the transmitter to authenticate to the receiver, normally with a
bearer token the receiver issued when the stream was configured. A receiver that
required it answered 401, the outbox retried eight times, and the event was
parked. Silently, and looking exactly like a receiver outage.

It is now read at delivery time and sent as `Authorization: Bearer`. Read at
delivery rather than carried in the outbox payload, because a queue table is the
last place a third party's credential should sit and rows there outlive the
delivery by design. It is sealed with the root key, so a database backup does not
hand it over.

A stream with no token still delivers. The SET is signed, so a receiver that
chose not to issue one is not made less safe by its absence — and failing closed
here would break every deployment that does not use stream tokens.

Confirmed on the wire. This is the complete request a receiver saw after a user
was deactivated through the admin API:

```
authorization: Bearer receiver-issued-token-abc123
content_type:  application/secevent+jwt
body:          eyJhbGciOiJFUzI1NiIs...   (ES256-signed SET)
```

## Verified against the running server

Sign in to a client with a registered stream, sign out, and the receiver gets:

```
content-type: application/secevent+jwt
typ: secevent+jwt   alg: ES256
aud: ['grouptest']
event: session-revoked
  subject: {'format': 'iss_sub', 'iss': 'https://auth.localhost:9443', 'sub': '3722a7c0-…'}
  initiating_entity: user
```

## Decisions

**Events are signed** (RFC 8417 Security Event Tokens). A receiver *acts* on
them — an unsigned "this session is revoked" is a denial of service anybody can
send.

**The audience is the receiver.** A SET with no audience, or the wrong one, is a
token one receiver can forward to another — which is how one relying party ends
another's sessions. Minting without an audience is refused outright.

**The subject is `iss_sub`, never an email address.** A receiver matching on
email is vulnerable to the same account confusion the federation code refuses;
the subject identifier we issued is the only thing both sides agree on.

**`event_timestamp` is in seconds**, and is when the thing *happened* — not when
the token was minted. Milliseconds here is a common silent interoperability bug:
the receiver reads a date forty thousand years out and either rejects the event
or orders it last forever.

**Subscriptions are an allow-list.** An empty subscription means *nothing*, not
everything. A receiver that registered without naming event types has not asked
to be told about credential changes, and sending them anyway discloses more
about the user than that receiver was given.

**Only events we actually emit are advertised.** A receiver subscribing to
something we never send waits forever for a signal that will not come.

**`initiating_entity` is reported honestly** — `user`, `admin`, `policy` or
`system`, mapped from the real termination reason. A receiver may treat an
administrator revoking a session differently from a user signing out, and
collapsing them throws away the distinction it would act on.

**Delivery reuses the existing outbox**: same retries, same capped backoff, same
parked-failure reporting as back-channel logout. It drains independently, so a
receiver that is down cannot hold up logout delivery to everybody else.

**Redirects are never followed.** The endpoint is configured; following one
would let whoever controls it forward a signed security event somewhere we never
approved.

## A bug worth recording

The first version emitted these events from inside the back-channel logout loop
— which only visits clients with a registered `backchannel_logout_uri`. A
receiver that subscribed to security events but does not implement back-channel
logout got **nothing at all, silently**.

They are different features for different audiences, and neither should be a
prerequisite for the other. Events are now queued from the session participants
directly.

## `SIGNARI_CA_BUNDLE`

Back-channel logout endpoints, SCIM targets and CAEP receivers are frequently
internal services behind a private certificate authority. Without a way to trust
one, what operators actually do is disable verification — so this adds a named
authority to the trust store for outbound deliveries. It *adds* to the system
pool, so trusting an internal CA does not quietly stop public endpoints from
verifying.

---

## Adversarial re-review, August 2026

Third pass over the receiver, this time against the **Shared Signals Framework
1.0 Final** text pulled fresh rather than recalled, and with hostile input rather
than one-field-wrong variations.

Why this surface and not another: accepting one forged Security Event Token
terminates a named person's sessions. Anybody who gets a SET past this code has a
repeatable denial of service against any user in the organisation.

### A real defect: `aud` may be a single string

§4.1.8, verbatim:

> The "aud" claim can be a single string or an array of strings.

RFC 7519 §4.1.3 says the same for every JWT, and **three of the Shared Signals
specification's own example SETs use the string form** — Figures 8, 9 and 10 all
carry `"aud": "636C69656E745F6964"`.

We parsed it as `[]string` only. The consequence is worse than a failed audience
check: Go's `encoding/json` reports a type mismatch, so the **whole claim set**
fails to unmarshal and the receiver answers `malformed claims`. An operator
connecting a conformant transmitter is told their token is malformed, with
nothing pointing at the audience, while every event is silently dropped.

Fixed with a custom unmarshaller that accepts both forms, and the string form is
still *checked* — `TestAStringAudienceNamingSomebodyElseIsStillRefused` exists so
the fix cannot become "accept any string".

This is the same defect class this review has hit before: **the base RFC and the
profile were both consulted, and the permissive half of the base RFC was
overlooked** because the profile's own examples were not read as test vectors.

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

The last two matter as much as the refusals. §4.2.3 makes ignoring unknown fields
a **MUST**, and it sits directly beside the rule that an unknown event *type* is
refused — a pair that is easy to conflate into "reject anything unfamiliar",
which would make every transmitter extension a breaking change.

### Which defences are actually load-bearing

Mutation testing answered a question reading could not: of four guards in the
verification path, **two are inherited from go-jose rather than enforced by us.**

| Guard | Removing it breaks a test? |
|---|---|
| `iss` pinned to the source configuration | **yes** |
| `jwk` / `jku` / `x5u` self-supplied keys refused | **yes** |
| Explicit algorithm allow-list excluding HS256 | **no** — go-jose refuses an HS256 signature against an ECDSA key on type grounds |
| Exactly one signature | **no** — `JSONWebSignature.Verify` declines a multi-signature object and requires `VerifyMulti` |

Both survivors were investigated rather than assumed. Neither is a hole: the
attacks are refused either way, verified by actually mounting them. But the
comments in the test file now say **which** check fires, because two of the tests
originally implied our guard was doing work that the library was doing.

That distinction is not pedantry. A JOSE library change, or a future need for
`VerifyMulti`, would make our guards the only thing standing — and nothing in the
suite would have told us they had been decorative all along. This is the same
failure this project has already found twice in its own comments, and finding it
a third time in a *test* is the reason the mutation pass exists.
