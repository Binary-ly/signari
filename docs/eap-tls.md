# EAP-TLS: certificate-based wifi and network login

```sh
SIGNARI_RADIUS_ADDR=0.0.0.0:1812
SIGNARI_EAP_TLS_CERT=/etc/signari/radius.pem     # supplicants verify this
SIGNARI_EAP_TLS_KEY=/etc/signari/radius.key
SIGNARI_EAP_CLIENT_CA=/etc/signari/device-ca.pem # issues supplicant certificates
SIGNARI_EAP_IDENTITY_FROM=cn                     # cn | email | upn
```

```sh
signari radius add-client -org <uuid> -name "office-ap" \
  -network 10.0.0.0/24 -secret "$(head -c 24 /dev/urandom | base64)"
```


## The one login method phishing cannot touch

There is no password anywhere in this flow. The user's identity is their
certificate; the authentication is that they hold its private key. There is
nothing for a person to be persuaded to type into a convincing page, and nothing
for a mobile operator to be persuaded to move to a different SIM.

That is the same property `phishing_resistant: true` describes for a passkey —
see [SMS](sms.md) for why that distinction is written into the policy language.

## What this actually is

A complete TLS handshake, with client authentication, carried inside EAP
packets, carried inside RADIUS attributes, over UDP. The access point
understands none of it and only forwards.

The handshake is run by `crypto/tls`, not reimplemented. Everything in
`internal/radius/eaptls.go` is transport: feeding the TLS state machine bytes
as they arrive across many round trips, and pulling its output back out to
fragment into the next challenge.

## Two fragmentations, one word

This is where implementations go wrong, because the word means two different
things one inside the other:

| | |
|---|---|
| **RADIUS** | one attribute holds 253 bytes, so a single EAP packet is split across consecutive `EAP-Message` attributes and concatenated in order |
| **EAP-TLS** | a TLS flight is far larger than one EAP packet, so it is split across several *round trips* using the More flag |

Treating either as the other produces a server that works with one supplicant
and not another. A small certificate fits in a single fragment and hides the bug
completely — it appears the first time somebody deploys a real certificate
chain.

Both directions are tested, and the tests **count fragments** so they cannot
pass without fragmenting:

```
client sent 7 fragments        (a padded client certificate)
server sent 8 fragments        (a padded server certificate)
server 6 fragments, client 6   (both, which is the real deployment)
```

The first version of the fragmentation test was wrong in an instructive way: the
test supplicant sent its whole 6 KB certificate in one frame, the RADIUS packet
exceeded 4096 bytes, and the server silently dropped it — exactly what a real
access point would do. The failure was in the harness, and finding out required
running it.

## A valid certificate is not a login

The TLS layer proves two things: the certificate chains to a configured
authority, and the supplicant holds the private key. Neither says whether the
person still works here.

A deactivated employee's certificate stays cryptographically perfect until it
expires. Revoking it needs a CRL or OCSP the access point may never consult;
deactivating the account takes effect at the next association. So the account
status is checked on every authentication:

```
deactivate the account, certificate unchanged   → Access-Reject + EAP-Failure
reactivate                                      → Access-Accept
```

## The keys nobody remembers

An Access-Accept without MPPE keys authenticates the supplicant and then leaves
it unable to encrypt anything. On wifi the association succeeds and no traffic
passes — a failure that looks like a driver fault and is not.

The keys are derived with the TLS exporter (RFC 5216 §2.3, and RFC 9190's
different label for TLS 1.3) and encoded into the Microsoft vendor attributes
every access point expects. The MD5 in that encoding is not a choice; it is what
RFC 2548 specifies and what every access point implements.

Note the ordering: the peer's **receive** key is the first half of the MSK and
its **send** key the second — the opposite way round from the attribute names,
which are written from the access point's point of view. Swapping them produces
a supplicant that associates and then cannot decrypt anything.

## Which field is the identity

`SIGNARI_EAP_IDENTITY_FROM` picks where the username comes from:

| | |
|---|---|
| `cn` | subject common name — what most internal PKI uses |
| `email` | an `rfc822Name` in the subject alternative name |
| `upn` | the Microsoft `userPrincipalName` SAN |

`upn` matters for Active Directory: AD-issued certificates put the identity
there and leave the common name as a display string, so a deployment matching on
CN against AD certificates matches the wrong field or nothing at all.

The EAP identity the supplicant *announces* is never used to decide anything —
RFC 5216 is explicit that it is unauthenticated. It is logged, and the
`User-Name` in the Access-Accept is taken from the certificate, so an access
point that authorises on it is acting on something proven.

## Bounded, because the source is unauthenticated

A conversation spans many UDP packets and each one makes the server hold a TLS
handshake in memory. Sessions are capped at 256, expire after 60 seconds, and
are keyed by a random `State` the supplicant must echo. At the cap the **oldest**
are dropped rather than refusing new ones — refusing would let an attacker who
fills the table lock every legitimate user out.

## Verified against a running binary

The in-process tests prove the protocol. A standalone supplicant over real UDP
proves the wiring — that `signari serve` reads the environment, opens the
socket, unseals the client secret, runs the handshake, and looks the certificate
up in the database:

```
RESULT: Access-Accept
  User-Name from the certificate: probe2@example.test
  MPPE key attributes: 2
  TLS: TLS 1.3, cipher 0x1301
  MSK derived: 64 bytes
```

| | |
|---|---|
| valid certificate | Access-Accept, name from the certificate |
| account deactivated | **Access-Reject** + EAP-Failure |
| reactivated | Access-Accept |
| certificate from another CA | Access-Reject |
| wrong shared secret | **silence** — no answer at all |

The last one is the existing RADIUS behaviour and worth keeping in view:
answering would confirm a RADIUS server is here and turn the port into a
discovery tool.

## Partial configuration is fatal

```
signari: configuring EAP-TLS: SIGNARI_EAP_CLIENT_CA is required: without the
authorities that issue supplicant certificates there is nothing to verify one
against, and the handshake would admit anybody holding any certificate
```

All three settings or none. A server certificate without client CAs would
complete handshakes with anybody holding any certificate — worse than no
EAP-TLS at all, because it looks like it is working.

## Not implemented

- **PEAP and EAP-TTLS.** Password-based methods tunnelled inside TLS. Absent
  deliberately: they exist to carry a password, and this engine's answer to
  "wifi with a password" is a passkey or a certificate. A supplicant that asks
  for EAP when EAP-TLS is not configured is **refused**, not offered something
  weaker.
- **CRL and OCSP checking.** The account-status check above covers the case that
  matters — somebody leaving — and does it faster than a revocation list
  propagates. A stolen laptop with a live account is a revocation problem, and
  that is the gap.
- **RADIUS accounting.** A separate protocol with separate risks.
