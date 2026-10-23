# RADIUS

For VPNs, wireless controllers and switches that authenticate users by RADIUS.

```sh
# Register the devices allowed to ask.
signari radius add-client -org <org-uuid> \
  -name "office wifi controller" \
  -network 10.0.0.0/24 \
  -secret "<shared secret configured on the device>"

signari radius list

# Then start the listener.
SIGNARI_RADIUS_ADDR=0.0.0.0:1812 \
SIGNARI_RADIUS_ORG_ID=<org-uuid> \
  signari serve
```

The Admin API registers devices, revokes them and places groups on VLANs the
same way, under `/admin/organizations/{orgID}/radius-clients` and
`/admin/groups/{groupID}/radius`; see [admin-api.md](admin-api.md).

Networks may overlap. A packet is checked against the **most specific** network
that contains its source address, so a `/24` for a controller inside a `/16`
for the building uses the controller's secret. Two entries for exactly the same
network are refused when they are added.

A network that covers every address is refused, whether it is written as
`0.0.0.0/0`, as `::/0`, or as the IPv4-mapped `::ffff:0.0.0.0/96`. An
IPv4-mapped network is read as the IPv4 network it means, both when it is added
and when it is loaded. The mapped `/96` passed the old check, because 96 bits
are not zero. Yet it matched every IPv4 source, and at 96 bits it outranked
every real range under most-specific matching.

## A correction

An earlier version of this page documented `SIGNARI_RADIUS_CLIENTS` as the way to
configure devices. **That variable never existed.** Nor did the listener:
`internal/radius` was complete, tested against CVE-2024-3596, and imported by
nothing at all — so `signari serve` had no way to answer an Access-Request, while
this page and the roadmap both recorded RADIUS as working.

Every test passed throughout, because tests prove a package behaves and say
nothing about whether anything calls it. It was found by grepping for importers
of `internal/radius` and getting no results, next to `internal/ldapd` which the
CLI imports.

The listener now exists and is verified below.

## Clients live in the database

Not in an environment variable, for two reasons. The console can show them, and
the shared secret can be sealed with the root key — the one credential in this
system stored **encrypted rather than hashed**, because RADIUS computes HMAC-MD5
over a request with the secret itself and needs the value, not a verifier.

The source range is part of the credential, not a convenience. RADIUS has no
handshake and no certificate, so the address and the secret are the only two
things distinguishing a real switch from anybody who can send a UDP packet.
`0.0.0.0/0` is refused at registration, and a secret under 16 characters is
refused too.

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

**A request means one thing.** One with a second User-Name, a second
User-Password or a second State is rejected. Until October 2026 only a second
User-Name was. With two passwords the first was checked, so a request carrying
the right one first and anything after it was accepted, and a proxy that read
the other would have checked something else.

**A certificate chain is reassembled up to one megabyte**, whatever its
fragments declare. The cap used to hold only when the first fragment declared a
total length, so a supplicant that declared none could grow the buffer for as
long as it kept sending.

**Binds go through the same credential path** as every other way into this
product — same Argon2 parameters, same throttling, same audit trail. That
includes the budget [LDAP](ldap.md) claims before verifying a password.

**An Access-Request has five seconds**, the wait for the shared hasher
included, and is rejected after that. Packets are answered one at a time, and
the verification waits for the hasher slots the sign-in form also uses. Without
a deadline, one packet could hold the listener while a sign-in flood kept
the slots busy, long after the client had retransmitted and given up.

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


## Verified on the wire

Against `signari serve` with a listener bound, using a RADIUS client written
separately from the engine:

| request | result |
| --- | --- |
| valid credentials | Access-Accept, `Message-Authenticator` verified |
| wrong password | Access-Reject, `Message-Authenticator` verified |
| **no `Message-Authenticator`** | **silence** — this is CVE-2024-3596 |
| wrong shared secret | silence |
| source outside the registered range | silence |

Silence rather than a rejection is deliberate for the last three: replying at all
confirms a RADIUS server is here and turns the port into a discovery tool.

The response `Message-Authenticator` is verified by the test client against the
**request** authenticator, per RFC 3579 §3.2 — the check that caught our own
Access-Accept failing our own verification when this was first written.

## One credential path

RADIUS authentication goes through the same code as every other way in, with the
same Argon2 parameters, the same throttling and the same audit trail. A protocol
front end with its own quiet password check routes around every control the rest
of the system has, so `RADIUSAuthenticator` is a thin wrapper over the LDAP
shim's authenticator rather than its own query.

The same path also decides what PAP does for somebody the sign-in page would ask
for a second factor. PAP carries only a password, so an organisation set to
`refuse_when_mfa` sends an Access-Reject (the default since migration 0128). See
[a password alone, and a second factor](ldap.md#a-password-alone-and-a-second-factor).

The identity is discarded: an Access-Accept carries no user attributes here,
because a network device did not ask for a directory and should not be handed
one.
