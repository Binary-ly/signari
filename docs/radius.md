# RADIUS

For VPNs, wireless controllers and switches that authenticate users by RADIUS.

```
SIGNARI_RADIUS_ADDR=0.0.0.0:1812
SIGNARI_RADIUS_CLIENTS="10.0.0.0/8=<shared-secret>"
```

Access-Request only. Accounting and change-of-authorization are separate
protocols with separate risks, and answering a code we do not implement invites
a device to believe we do.

## Built around CVE-2024-3596 (Blast-RADIUS)

RADIUS authenticates responses with an MD5 "Response Authenticator". MD5
chosen-prefix collisions are practical, and the published attack turns that into
forgery. From the NVD entry:

> "susceptible to forgery attacks by a local attacker who can modify any valid
> Response (Access-Accept, Access-Reject, or Access-Challenge) to any other
> response using a chosen-prefix collision attack against MD5 Response
> Authenticator signature."

An attacker on the path turns a **reject into an accept**.

The published short-term mitigation is to "mandate that clients and servers
always send and require `Message-Authenticator` attributes for _all_ requests
and responses", included "as the _first_ attribute" in accept and reject
responses. `Message-Authenticator` is HMAC-MD5, which is unaffected by the
collision attacks that break bare MD5.

So this server:

- **Refuses** an Access-Request carrying no `Message-Authenticator`. Not a
  warning, not a setting — a request without it cannot be authenticated, and
  accepting it *is* the vulnerability. Verified: such a request gets **no reply
  at all** and never reaches the credential checker.
- **Always emits** `Message-Authenticator`, **first**, in every response.

The real answer is RADIUS over TLS (RFC 6614), which removes the attacker's
position entirely. That is a deployment decision; run this on a network segment
you trust, or in front of a TLS terminator.

## Other decisions

**An unconfigured source gets silence, not a rejection.** Replying would confirm
a RADIUS server is here and turn the port into a discovery tool.

**Shared secrets must be at least 16 characters**, enforced at configuration
time. RADIUS hands an attacker offline material to grind against, and this
secret is the only thing between a network device and an authentication oracle.

**The reject message is identical for every failure.** A device shows it to
whoever is typing, so distinguishing "no such user" from "wrong password" makes
the network login screen a user-enumeration oracle.

**Empty passwords are rejected** before the credential checker, matching the
LDAP shim's rule about unauthenticated binds.

**Packets are handled inline, not one goroutine each.** UDP has no handshake, so
a goroutine per datagram is a spawn primitive for anybody who can send packets —
and the work here is one Argon2 verification, which is deliberately expensive.

**A zero-length attribute is refused.** It would not advance the parse cursor,
so the loop would spin forever on a packet an attacker sends once.

**Binds go through the same credential path** as every other way into this
product — same Argon2 parameters, same throttling, same audit trail.

## The bug the round-trip caught

Our own Access-Accept failed our own verification.

RFC 3579 §3.2: a **response's** `Message-Authenticator` is computed over the
packet carrying the **request** authenticator — and the sender then overwrites
those same sixteen bytes with the Response Authenticator before transmitting. A
receiver therefore cannot verify a response from the response alone; it has to
substitute back the request authenticator it sent.

Verifying a response against its own bytes fails every time. That is not a
theoretical distinction: it is what network equipment does, so every
Access-Accept we sent would have been discarded by the device that asked for it.

Found by round-tripping our own response through our own verifier — a test that
only exists because "we sign it and we check it" is exactly the pair that can be
consistently wrong together.
