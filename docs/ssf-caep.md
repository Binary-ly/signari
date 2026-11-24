# Shared Signals and CAEP

## Introduction

An access token stays valid until it expires, even after the session behind it ends.
An application that trusts the token keeps letting the person in for the rest of
the token's lifetime.

Continuous access evaluation closes that gap. Applications subscribe to a stream of
security events about people they have seen, and react as the events arrive. The
Shared Signals Framework ([SSF](glossary.md#shared-signals)) carries the stream. The
Continuous Access Evaluation Profile ([CAEP](glossary.md#caep)) defines events such
as "this session was revoked".

Signari is the "transmitter" that sends the events, and each application runs a
"receiver" that takes them. You register a stream for an application with
`signari ssf add-stream`, or through the Admin API.

## The argument

An access token is valid until it expires. That is the whole security model of a
bearer token. It means an application keeps honouring one for its full lifetime.
That holds after the session behind it was revoked, the password was changed, or the
account was disabled.

Short lifetimes narrow that window, but they do not close it. Shortening them costs
a token request every few minutes for each person.

CAEP closes it by **telling** the application. When a session is revoked here,
every receiver that has seen that person learns within seconds.

This project has made the same argument about sign-out from the start: a sign-out
nobody can prove happened is not a sign-out. CAEP is that argument applied
continuously instead of once.

## Registering a receiver

Register a stream for an application's client, either pushed to the receiver's
endpoint or polled by the receiver, then list the streams:

```sh
# Push (RFC 8935): we POST each event to the receiver's endpoint.
signari ssf add-stream -org <org-uuid> -client-id <client> \
  -endpoint https://receiver.example.com/events \
  -receiver-token "<bearer token the receiver issued us>"

# Poll (RFC 8936): the receiver pulls from us instead. No endpoint.
signari ssf add-stream -org <org-uuid> -client-id <client> -poll

signari ssf list
```

There was no way to do this until recently. A stream could only be created by
hand-written SQL, which is how it was first tested. A feature nobody can configure
is one nobody uses.

A stream is registered in its client's own organisation. It carries events about the
people who signed in to that client. So a stream named under another organisation
would send them to a receiver that organisation never chose.

The Admin API registers streams and changes their status the same way, at
`/admin/organizations/{orgID}/ssf-streams` and
`/admin/clients/{clientID}/ssf-stream`. See the [Admin API reference](admin-api.md).

## Pausing and disabling a stream

Pause a stream with a reason, enable it again, or disable it:

```sh
signari ssf set-status -org <org-uuid> -client-id <client> -status paused -reason "receiver maintenance"
signari ssf set-status -org <org-uuid> -client-id <client> -status enabled
signari ssf set-status -org <org-uuid> -client-id <client> -status disabled
```

The three statuses are SSF 1.0 §8.1.2.1's, and each does what it says there:

| Status | Events | |
|---|---|---|
| `enabled` | sent | |
| `paused` | **held**, not sent | released when the stream is enabled again |
| `disabled` | neither sent nor held | what it held is discarded |

The status is read when an event is delivered, not only when it is queued. So an
event queued a moment before a pause is held with the rest, rather than sent.

The receiver is told. Pausing or disabling an enabled stream first queues a
`stream-updated` event, carrying the new status and your `-reason`. Enabling one
sends another, as §8.1.5 requires. Its subject is the stream itself, in the `opaque`
format with the stream's ID.

That notice is the one thing a paused or disabled stream still delivers, by push or
by poll. A poll receiver on a paused stream collects its `stream-updated` events and
nothing else. Moving between `paused` and `disabled` sends nothing, because neither
may transmit.

There was no way to change a stream's status before: the column was read and nothing
wrote it.

## Poll delivery (RFC 8936)

Push assumes the receiver can accept an inbound HTTPS POST. A receiver behind a
firewall, or an agent with no public address, cannot. And those are often the
receivers that most want continuous signals.

Poll inverts the direction. The receiver makes an authenticated request to
`POST /ssf/poll`, and Signari hands back the Security Event Tokens (SETs) waiting
for it. The receiver acknowledges the ones it has stored, so Signari drops them.

A stream is push **or** poll, set when it is registered. A poll stream has no
endpoint, so `-endpoint` and `-receiver-token` are refused with `-poll`. The
receiver authenticates to Signari as its own OAuth client, with HTTP Basic or mutual
Transport Layer Security ([TLS](glossary.md#mutual-tls)). That is a credential Signari already verifies,
rather than a token it would have pushed.

The exchange, per §2.4:

```
POST /ssf/poll                       -> { "sets": { "<jti>": "<signed SET>" },
Authorization: Basic <client creds>       "moreAvailable": false }
{ "maxEvents": 10, "ack": ["<jti>"] }
```

`ack` names SETs from a previous poll, and naming one deletes it. A SET handed over
but not acknowledged is **redelivered** on the next poll. A receiver that crashed
before storing an event does not lose it.

Set `returnImmediately: false` to have Signari hold the connection briefly, and
return as soon as an event is queued. Otherwise it answers with an empty set
straight away.

The same event is minted the same way, whichever direction it travels. One builder
(`ssf.RevocationEvent`) is shared by the push worker and the poll handler. So a
receiver that later switches from push to poll sees no change in what a SET says.

An abandoned poll stream cannot grow without bound. The janitor drops events that
have waited far longer than any live receiver would leave them (30 days).

## Asking whether a stream works

A quiet stream and a broken one look the same from the receiver's side. So a
receiver can ask for an event (§8.1.4). `signari ssf list` shows each stream's ID,
and the receiver asks like this:

```
POST /ssf/verify                     -> 204 No Content
Authorization: Basic <client creds>
{ "stream_id": "<id>", "state": "<anything>" }
```

The receiver authenticates as it does to poll: as the stream's own client, with HTTP
Basic or a certificate. The event is an ordinary SET. Its `sub_id` is the stream,
`{"format": "opaque", "id": "<stream_id>"}`, and its `state` is what the request
sent.

It travels by the stream's own delivery method. So `204` means it is queued, not
that it arrived, and receiving it is the proof.

These are the answers to a request that fails:

| The request | The answer |
|---|---|
| a body that does not parse, or no `stream_id` | `400` |
| a disabled stream, which holds nothing and would never send it | `400` |
| no credentials, or the wrong ones | `401` |
| a stream that does not exist or belongs to another client | `404` |
| a second request for a stream in the same 30-second window | `429`, with `Retry-After` |

A paused stream answers `204` and holds the event with the rest of what it is
holding. The 30 seconds is the stream's `min_verification_interval`. The windows
are the clock's, starting on each minute and half minute, so two requests 30
seconds apart are never refused, and two a moment apart on either side of a
window's start are both answered. `Retry-After` is the seconds left in the window
that refused the request.

## What a receiver can do with its stream

An administrator makes a stream and says where it delivers, because that decides who
hears about whom. A receiver reads and changes the rest of its own stream. It
authenticates as it does to poll and to verify: as the stream's client, with HTTP
Basic or a certificate.

| Request | What it does |
|---|---|
| `GET /ssf/stream`, `?stream_id=<id>` | The configuration, or a list of the one stream a client has, which is `[]` for a client with none |
| `PATCH /ssf/stream` | Changes `events_requested` and `description`, and leaves alone what it does not name |
| `PUT /ssf/stream` | Replaces them, so what it leaves out is gone |
| `GET /ssf/status?stream_id=<id>` | `enabled`, `paused` or `disabled` |
| `POST /ssf/status` | Sets it, with what [pausing](#pausing-and-disabling-a-stream) does from here |
| `POST /ssf/subjects:add`, `:remove` | Says whether it wants to hear about a person |
| `POST`, `DELETE /ssf/stream` | `403`. A stream is made and deleted with `signari ssf add-stream` or the Admin API |

An event type Signari does not understand is dropped from `events_requested`, as the
specification says. A property Signari supplies may be sent back, but it has to
match, or the answer is `400`.

A `delivery` that differs is `403`, whatever a receiver sends. A stolen client secret
should not be enough to send people's events somewhere else.

Each change is in the audit trail as `ssf.stream_changed`, and moves the
configuration version, because it is a change to the administrator's stream as well.
`signari plan` will show it as drift from a file that says otherwise.

### Subjects

A stream carries events about the people its client has met, and that does not
change. So adding a subject asks for nothing more: it takes back a removal. Removing
one stops events about that person on this stream, push or poll, until it is added
back.

A person is named as Signari's events name them,
`{"format": "iss_sub", "iss", "sub"}`, or by `email`. Either can also be under
`user` in a `complex` subject.

The answer is an empty `200` whoever the subject is, in any format, known or not. An
answer that differed would tell a receiver who has an account here.

## The token that was never sent

`ssf_streams.auth_token` existed from the first migration, with a comment saying it
"authenticates US to THEM". And **nothing ever sent it**.

RFC 8935 push delivery expects the transmitter to authenticate to the receiver. It
normally does that with a bearer token the receiver issued when the stream was
configured. A receiver that required it answered 401, the outbox retried eight
times, and the event was parked. Silently, and looking exactly like a receiver
outage.

It is now read at delivery time, and sent as `Authorization: Bearer`. It is read at
delivery rather than carried in the outbox payload. A queue table is the last place
a third party's credential should sit, and rows there outlive the delivery by
design. It is sealed with the root key, so a database backup does not hand it over.

A stream with no token still delivers. The SET is signed, so a receiver that chose
not to issue one is not made less safe by its absence. And failing closed here would
break every deployment that does not use stream tokens.

Confirmed on the wire. This is the complete request a receiver saw after a person
was deactivated through the Admin API:

```
authorization: Bearer receiver-issued-token-abc123
content_type:  application/secevent+jwt
body:          eyJhbGciOiJFUzI1NiIs...   (ES256-signed SET)
```

## Verified against a running engine

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

**Events are signed** (RFC 8417 Security Event Tokens). A receiver *acts* on them,
so an unsigned "this session is revoked" is a denial of service anybody can send.

**The audience is the receiver.** A SET with no audience, or the wrong one, is a
token one receiver can forward to another. That is how one application ends
another's sessions. Minting without an audience is refused outright.

**The subject is `iss_sub`, never an email address.** A receiver matching on email
is vulnerable to the same account confusion the federation code refuses. The subject
identifier Signari issued is the only thing both sides agree on.

**`event_timestamp` is in seconds**, and is when the thing *happened*, not when the
token was minted. Milliseconds here is a common silent interoperability bug. The
receiver reads a date forty thousand years out, and either rejects the event or
orders it last forever.

**Subscriptions are an allow-list.** An empty subscription means *nothing*, not
everything. A receiver that registered without naming event types has not asked to
be told about session revocations. Sending them anyway discloses more about the
person than that receiver was given.

**Only events Signari actually emits are advertised.** A receiver subscribing to
something Signari never sends waits forever for a signal that will not come.
Credential-change was once advertised and accepted in `ssf add-stream -events` while
nothing emitted it. So a test now walks a person through each change, and fails on
any advertised event that never arrives.

Four are offered. The account events come from Risk Incident Sharing and
Coordination (RISC), a companion set of events to CAEP:

| Event | Sent when |
|---|---|
| CAEP `session-revoked` | a session ends |
| CAEP `credential-change` | a password, authenticator app or hardware token, Duo enrolment, text-message number or passkey is added, replaced or removed |
| RISC `account-disabled` | an active account is deactivated, by whatever path |
| RISC `account-enabled` | a deactivated account is reactivated, by whatever path |

A credential change names itself with `credential_type` (`password`, `app`,
`phone-sms`, `fido2-platform`, `fido2-roaming`), `change_type` (`create`, `update`,
`delete`) and `initiating_entity`. An emailed code and a recovery code have no word
in CAEP's list, so changing them says nothing.

A sign-in that upgrades a stored hash is not a credential change, because the
password is the one it was. `session-revoked` stays the default for `-events`. The
other three have to be asked for.

**A stream hears of the people its client has met**: anyone with a session or a
refresh token from that client, live or not. It has to include sessions that have
ended. Deactivating somebody ends their sessions in the same transaction, and those
are the applications that need telling.

**`initiating_entity` is reported honestly**: `user`, `admin`, `policy` or `system`,
mapped from the real termination reason. A receiver may treat an administrator
revoking a session differently from a person signing out. Collapsing them throws
away the distinction it would act on.

**Delivery reuses the existing outbox**: the same retries, the same capped backoff,
and the same parked-failure reporting as Back-Channel Logout. It drains
independently, so a receiver that is down cannot hold up sign-out delivery to
everybody else.

**Redirects are never followed.** The endpoint is configured. Following a redirect
would let whoever controls it forward a signed security event somewhere Signari
never approved.

## A bug worth recording

The first version emitted these events from inside the Back-Channel Logout loop,
which only visits clients with a registered `backchannel_logout_uri`. A receiver
that subscribed to security events, but does not implement Back-Channel Logout, got
**nothing at all, silently**.

They are different features for different audiences, and neither should be a
prerequisite for the other. Events are now queued from the session participants
directly.

## `SIGNARI_CA_BUNDLE`

Back-Channel Logout endpoints, System for Cross-domain Identity Management
([SCIM](glossary.md#scim)) targets and CAEP receivers are often internal services
behind a private certificate authority. Without a way to trust one, what
administrators actually do is disable verification.

So this setting adds a named authority to the trust store for every outbound call.
That covers deliveries, and the receiver's fetch of a transmitter's keys, which until
October 2026 ignored it. It *adds* to the system pool, so trusting an internal
authority does not quietly stop public endpoints from verifying.

The reviews of Signari's receiver, kept as they were written, are on [receiving
Shared Signals](shared-signals-receiver.md), with the receiver itself.
