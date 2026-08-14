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
