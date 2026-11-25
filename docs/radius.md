# RADIUS

## Introduction

Network equipment, such as a virtual private network (VPN), a wifi controller or
a switch, has to ask whether someone may connect. Most of it asks with Remote
Authentication Dial-In User Service ([RADIUS](glossary.md#radius)). The device
sends the person's username and password, and gets back yes or no. Acme's VPN
works this way.

Signari can answer those questions as a RADIUS server, with the same password
check as the sign-in page. In RADIUS's words, each device that asks is a
"client". Signari answers only the devices you have registered. Each one has a
"shared secret", a password that the device and Signari both hold. [Which
protocol do I need?](protocols-explained.md#radius) explains RADIUS in plain
words.

You register devices with the command line or the Admin API. You turn the
listener on with environment variables when you start Signari.

> [!NOTE]
> A device can also prove itself with a certificate instead of a password, using
> the Extensible Authentication Protocol with Transport Layer Security. See
> [EAP-TLS](eap-tls.md).

## Register a device and start the listener

To let a device ask, register it with the network it sends from and its shared
secret. Then start the listener on port 1812:

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

The Admin API registers devices and revokes them the same way, under
`/admin/organizations/{orgID}/radius-clients`. It places groups on virtual LANs
(VLANs) under `/admin/groups/{groupID}/radius`. See [the Admin API](admin-api.md).

## Give a group's members network settings

When Signari says yes, it sends an "Access-Accept". A group can give its members
more than a VLAN in that answer. An Access-Accept says the same thing whether the
person arrived with a password or a certificate. This command gives the
`network-admins` group a VLAN, a filter, a session length, a class and a vendor
attribute:

```sh
signari radius authorize --org=<org-uuid> --group=network-admins --vlan=20 \
  --filter-id=staff --session-timeout=28800 --radius-class=staff \
  --vendor-attributes=9:1=shell:priv-lvl=15
```

Each flag sets these RADIUS attributes:

| Flag | Attribute | |
|---|---|---|
| `--vlan` | Tunnel-Type, Tunnel-Medium-Type, Tunnel-Private-Group-ID | 1 to 4094. |
| `--filter-id` | Filter-Id | A filter list already on the device. |
| `--session-timeout` | Session-Timeout | Seconds the device may keep the session. |
| `--radius-class` | Class | Opaque to the device, which echoes it in accounting. |
| `--vendor-attributes` | Vendor-Specific | `vendor:type=value`, comma-separated. |

A vendor attribute is given by number, because the engine carries no dictionary.
It has three parts:

- The vendor's Internet Assigned Numbers Authority (IANA) enterprise number.
- The attribute number from the vendor's documentation.
- A value of up to 247 bytes, sent as it stands.

Only the first `=` divides, so a value can hold more. A value holding a comma is
given in a [configuration file](config-as-code.md) or through the Admin API
instead.

Somebody in several authorised groups gets the one with the highest `--priority`,
ties broken by group ID. They get only that group's attributes: they are not
merged.

## Networks that overlap

Networks may overlap. A packet is checked against the **most specific** network
that contains its source address. So a `/24` for a controller inside a `/16` for
the building uses the controller's secret. Two entries for exactly the same
network are refused when they are added.

A network that covers every address is refused, whether it is written as
`0.0.0.0/0`, as `::/0`, or as the IPv4-mapped `::ffff:0.0.0.0/96`. An IPv4-mapped
network is read as the IPv4 network it means, both when it is added and when it
is loaded.

The mapped `/96` passed the old check, because 96 bits are not zero. Yet it
matched every IPv4 source, and at 96 bits it outranked every real range under
most-specific matching.

## A correction

An earlier version of this page documented `SIGNARI_RADIUS_CLIENTS` as the way to
configure devices. **That variable never existed.** Nor did the listener.
`internal/radius` was complete, tested against CVE-2024-3596, and imported by
nothing at all. So `signari serve` had no way to answer an Access-Request, while
this page and the roadmap both recorded RADIUS as working.

Every test passed throughout, because tests prove a package behaves and say
nothing about whether anything calls it. It was found by searching for importers
of `internal/radius` and getting no results, next to `internal/ldapd`, which the
command line imports.

The listener now exists, and is verified below.

## Clients live in the database

Devices are not kept in an environment variable, for two reasons. The console can
show them, and the shared secret can be sealed with the root key. It is the one
credential in Signari stored **encrypted rather than hashed**. RADIUS computes
HMAC-MD5 over a request with the secret itself, so it needs the value, not a
verifier.

The source range is part of the credential, not a convenience. RADIUS has no
handshake and no certificate. So only the address and the secret tell a real
switch from anybody who can send a UDP packet, the plain network message RADIUS
travels in. `0.0.0.0/0` is refused at registration, and a secret under 16
characters is refused too.

Signari answers Access-Request only. Accounting and change-of-authorization are
separate protocols with separate risks. Answering a code Signari does not
implement would invite a device to believe it does.

## Built around CVE-2024-3596 (Blast-RADIUS)

RADIUS authenticates responses with an MD5 "Response Authenticator". MD5
chosen-prefix collisions are practical, and the published attack turns that into
forgery. From the entry in the National Vulnerability Database (NVD):

> "susceptible to forgery attacks by a local attacker who can modify any valid
> Response (Access-Accept, Access-Reject, or Access-Challenge) to any other
> response using a chosen-prefix collision attack against MD5 Response
> Authenticator signature."

An attacker on the path turns a **reject into an accept**.

The published short-term mitigation is to "mandate that clients and servers
always send and require `Message-Authenticator` attributes for _all_ requests
and responses". It is included "as the _first_ attribute" in accept and reject
responses. `Message-Authenticator` is HMAC-MD5, which is unaffected by the
collision attacks that break bare MD5.

So this server:

- **Refuses** an Access-Request carrying no `Message-Authenticator`. Not a
  warning, not a setting. A request without it cannot be authenticated, and
  accepting it *is* the vulnerability. Verified: such a request gets **no reply
  at all**, and never reaches the credential checker.
- **Always emits** `Message-Authenticator`, **first**, in every response.

The real answer is RADIUS over Transport Layer Security
([TLS](glossary.md#tls)), in RFC 6614, which removes the attacker's position
entirely. That is a deployment decision. Run this on a network segment you trust,
or in front of a TLS terminator.

## Other decisions

**An unconfigured source gets silence, not a rejection.** Replying would confirm
that a RADIUS server is here, and turn the port into a discovery tool.

**Shared secrets must be at least 16 characters**, enforced at configuration
time. RADIUS hands an attacker offline material to grind against. This secret is
the only thing between a network device and an authentication "oracle", something
that answers yes or no to each guess.

**The reject message is identical for every failure.** A device shows it to
whoever is typing. Telling "no such person" apart from "wrong password" would turn
the network sign-in screen into an oracle for which accounts exist.

**Empty passwords are rejected** before the credential checker. That matches the
rule of the Lightweight Directory Access Protocol ([LDAP](ldap.md)) shim about
unauthenticated binds.

**A fixed set of workers answers, and only a device can make them work.** The
loop reading the socket checks the source and the Message-Authenticator. Only a
packet that passes takes a place in a queue of 1,024. UDP has no handshake, so a
goroutine per datagram would let anybody who can send packets start work at will.
A forged packet costs one HMAC here.

There are twice as many workers as the hasher has slots. So a slow password holds
up nobody behind it, and throughput is what the hasher can do. Past the queue a
packet is dropped, which a device treats as any lost datagram, and the log says how
many.

**A retransmission is answered, not asked again.** The same bytes from the same
source within thirty seconds get the same reply. While the first is still being
answered, they get nothing. Before this, a device retrying a wrong password
counted twice towards the budget. A retried code was refused because the first
had spent it, and an access point that missed an Accept was sent a Reject. The
packet is checked first, so a device disabled since is answered nothing.

**A supplicant can resume.** A "supplicant" is the software on the person's device
that joins the network. The session stays in Signari for eight hours, and the
supplicant holds a random name for it. That is because a sealed ticket carries the
client certificate, and costs what it saves.

With a three-kilobyte certificate, a resumption takes three round trips where the
whole handshake takes seven under TLS 1.2. It takes six where the handshake takes
nine under TLS 1.3. Certificate expiry and the chain are checked again, and the
owner is asked about again, so somebody deactivated since is refused. A restart,
or a node that does not know the name, means the whole handshake.

wpa_supplicant offers a ticket under TLS 1.2 only with
`tls_disable_session_ticket=0` in `phase1`. Without it, wpa_supplicant does the
whole handshake every time.

**EAP-TLS under TLS 1.3 follows RFC 9190.** Signari says it has accepted
somebody over TLS with one byte of application data, before EAP-Success. It says
so only after asking about the certificate's owner. So somebody refused is sent
EAP-Failure, and never that byte.

Until November 2026, that byte was not sent. The keys given to the access point
were also derived with the wrong arguments. So a real supplicant could finish only
under TLS 1.2.

This is checked with `eapol_test` from wpa_supplicant 2.10. It compares the keys
in the Accept with the ones it derived for itself. They match under both versions,
on a whole handshake and a resumed one. A response whose EAP Identifier is not the
outstanding request's is discarded with no reply, as RFC 3748 requires.

**A zero-length attribute is refused.** It would not advance the parse cursor, so
the loop would spin forever on a packet an attacker sends once.

**A request means one thing.** One with a second `User-Name`, a second
`User-Password` or a second `State` is rejected. Until October 2026, only a second
`User-Name` was. With two passwords, the first was checked. So a request carrying
the right one first, and anything after it, was accepted. A proxy that read the
other would have checked something else.

**A certificate chain is reassembled up to one megabyte**, whatever its fragments
declare. The cap used to hold only when the first fragment declared a total
length. So a supplicant that declared none could grow the buffer for as long as it
kept sending.

**Binds go through the same credential path** as every other way into Signari:
the same Argon2 parameters, the same throttling and the same audit trail. That
includes the budget [LDAP](ldap.md) claims before verifying a password.

**An Access-Request has five seconds from arrival**, the queue and the wait for
the shared hasher included. The verification waits for the hasher slots the
sign-in form also uses. Without a deadline, a flood of sign-ins could keep a worker
busy long after the client had retransmitted and given up. One that has waited
that long in the queue is dropped unanswered. One that runs out of time at the
hasher is rejected.

## The bug the round-trip caught

Signari's own Access-Accept failed Signari's own verification.

RFC 3579 §3.2: a **response's** `Message-Authenticator` is computed over the
packet carrying the **request** authenticator. The sender then overwrites
those same sixteen bytes with the Response Authenticator before transmitting. A
receiver therefore cannot verify a response from the response alone; it has to
substitute back the request authenticator it sent.

Verifying a response against its own bytes fails every time. That is not a
theoretical distinction, because it is what network equipment does. So every
Access-Accept Signari sent would have been discarded by the device that asked for
it.

It was found by sending Signari's own response round through Signari's own
verifier. That test only exists because "we sign it and we check it" is exactly
the pair that can be consistently wrong together.

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

Silence rather than a rejection is deliberate for the last three. Replying at all
confirms that a RADIUS server is here, and turns the port into a discovery tool.

The test client verifies the response's `Message-Authenticator` against the
**request** authenticator, per RFC 3579 §3.2. That is the check that caught
Signari's own Access-Accept failing its own verification, when this was first
written.

## One credential path

RADIUS authentication goes through the same code as every other way in, with the
same Argon2 parameters, the same throttling and the same audit trail. A protocol
front end with its own quiet password check routes around every control the rest
of the system has. So `RADIUSAuthenticator` is a thin wrapper over the LDAP shim's
authenticator, not its own query.

The same path also decides what the Password Authentication Protocol (PAP) does
for somebody the sign-in page would ask for a second factor. See [a password
alone, and a second factor](ldap.md#a-password-alone-and-a-second-factor).

Under `refuse_when_mfa`, the default since migration 0128, a right password with
no code is answered with an **Access-Challenge**. That is a prompt for the device
to show, and a State for its next request, which carries the code where the
password was. That State is good once, for two minutes, from that device and for
that person.

A device that shows no prompt sends `password;123456` in the one field. A State
lives in the node that issued it. So behind a balancer that does not keep a device
on one node, use the second form. Through a RADIUS outpost, only the second form
works, and a password alone is an Access-Reject.

The identity is discarded. An Access-Accept carries no attributes of the person here,
because a network device did not ask for a directory and should not be handed one.
