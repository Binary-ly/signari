# Certificate wifi and network sign-in (EAP-TLS)

## Introduction

Office wifi and other networks can check who joins them with a certificate
instead of a password. The device holds a certificate and its private key, and
proves that it holds the key. That is [EAP-TLS](glossary.md#eap-tls): the
Extensible Authentication Protocol (EAP) carrying a Transport Layer Security
(TLS) handshake. It suits company laptops on Acme's office wifi.

Signari answers EAP-TLS on its Remote Authentication Dial-In User Service
([RADIUS](radius.md)) listener. It checks the certificate against
the authority that issued it. Then it checks that the person the certificate names
still has an active account. For people with no certificate, Signari can also
check a password inside an encrypted tunnel.

You turn it on with environment variables, and register each access point as a
RADIUS client.

> [!NOTE]
> EAP-TLS runs over RADIUS, so read [RADIUS](radius.md) first. It explains the
> listener, and the devices that may ask it.

## Turn on EAP-TLS

The software on a device that joins the network is called the "supplicant". Give
Signari five settings. They are the listener's address, the certificate and key
that supplicants verify, the authority that issues their certificates, and the
field that names the person:

```sh
SIGNARI_RADIUS_ADDR=0.0.0.0:1812
SIGNARI_EAP_TLS_CERT=/etc/signari/radius.pem     # supplicants verify this
SIGNARI_EAP_TLS_KEY=/etc/signari/radius.key
SIGNARI_EAP_CLIENT_CA=/etc/signari/device-ca.pem # issues supplicant certificates
SIGNARI_EAP_IDENTITY_FROM=cn                     # cn | email | upn
```

Then register each wifi access point as a RADIUS client, with a random shared
secret:

```sh
signari radius add-client -org <uuid> -name "office-ap" \
  -network 10.0.0.0/24 -secret "$(head -c 24 /dev/urandom | base64)"
```


## The one sign-in method phishing cannot touch

There is no password anywhere in this flow. The person's identity is their
certificate, and they authenticate by holding its private key. There is nothing
for a person to be persuaded to type into a convincing page. There is nothing for
a phone company to be persuaded to move to a different SIM.

That is the same property `phishing_resistant: true` describes for a passkey. See
[text-message codes](sms.md) for why that distinction is written into the policy
language.

## What this actually is

EAP-TLS is a complete TLS handshake, with client authentication. It is carried
inside EAP packets, which are carried inside RADIUS attributes, over UDP. The
access point understands none of it, and only
forwards it.

The handshake is run by `crypto/tls`, not reimplemented. Everything in
`internal/radius/eaptls.go` is transport. It feeds the TLS state machine bytes as
they arrive across many round trips. Then it pulls the output back out, to
fragment into the next challenge.

## Two fragmentations, one word

This is where implementations go wrong. The word "fragmentation" means two
different things, one inside the other:

| | |
|---|---|
| **RADIUS** | one attribute holds 253 bytes, so a single EAP packet is split across consecutive `EAP-Message` attributes and concatenated in order |
| **EAP-TLS** | a TLS flight is far larger than one EAP packet, so it is split across several *round trips* using the More flag |

Treating either as the other produces a server that works with one supplicant and
not another. A small certificate fits in a single fragment, and hides the bug
completely. The bug appears the first time somebody deploys a real certificate
chain.

Both directions are tested, and the tests **count fragments** so they cannot pass
without fragmenting:

```
client sent 7 fragments        (a padded client certificate)
server sent 8 fragments        (a padded server certificate)
server 6 fragments, client 6   (both, which is the real deployment)
```

The first version of the fragmentation test was wrong in an instructive way. The
test supplicant sent its whole 6 KB certificate in one frame, and the RADIUS
packet exceeded 4096 bytes. Signari silently dropped it, exactly as a real
access point would. The failure was in the harness, and finding that out required
running it.

## A valid certificate is not a sign-in

The TLS layer proves two things: the certificate chains to a configured
authority, and the supplicant holds the private key. Neither says whether the
person still works here.

A deactivated employee's certificate stays cryptographically perfect until it
expires. Revoking it needs a certificate revocation list (CRL) or the Online
Certificate Status Protocol (OCSP), which the access point may never consult.
Deactivating the account takes effect at the next "association", the next time
the device joins. So the account status is checked on every authentication:

```
deactivate the account, certificate unchanged   → Access-Reject + EAP-Failure
reactivate                                      → Access-Accept
```

Every outcome is audited, with `via: eap-tls` and the certificate's serial. It is
recorded as `login.succeeded`, or as `login.failed` with reason `no_identity`,
`unknown_user` or `inactive`. It is recorded by the account's subject ID when
there is one.

Until October 2026, nothing recorded a certificate sign-in. The listener logged
the username, and nothing else said who had joined the network.

## The keys nobody remembers

An Access-Accept without MPPE keys authenticates the supplicant, then leaves it
unable to encrypt anything. On wifi, the association succeeds and no traffic
passes. It is a failure that looks like a driver fault, and is not.

The keys are derived with the TLS exporter (RFC 5216 §2.3, and RFC 9190's
different label for TLS 1.3). They are encoded into the Microsoft vendor
attributes every access point expects. The MD5 in that encoding is not a choice.
It is what RFC 2548 specifies, and what every access point implements.

Note the ordering. The peer's **receive** key is the first half of the master
session key (MSK), and its **send** key is the second. That is the opposite way
round from the attribute names, which are written from the access point's point
of view. Swapping them produces a supplicant that associates and then cannot
decrypt anything.

## Which field is the identity

`SIGNARI_EAP_IDENTITY_FROM` picks where the username comes from:

| | |
|---|---|
| `cn` | subject common name — what most internal PKI uses |
| `email` | an `rfc822Name` in the subject alternative name |
| `upn` | the Microsoft `userPrincipalName` SAN |

`upn` matters for Active Directory. Certificates issued by Active Directory (AD)
put the identity there, and leave the common name as a display string. So a
deployment matching on CN against AD certificates matches the wrong field, or
nothing at all.

The EAP identity the supplicant *announces* is never used to decide anything.
RFC 5216 is explicit that it is unauthenticated. It is logged, and the
`User-Name` in the Access-Accept is taken from the certificate. So an access point
that authorises on it is acting on something proven.

## Bounded, because the source is unauthenticated

A conversation spans many UDP packets, and each one makes Signari hold a TLS
handshake in memory. Sessions are capped at 256, and expire after 60 seconds.
They are keyed by a random `State` the supplicant must echo.

At the cap, the **oldest** are dropped, rather than new ones being refused.
Refusing would let an attacker who fills the table lock every legitimate person
out.

## Verified against a running binary

The in-process tests prove the protocol. A standalone supplicant over real UDP
proves the wiring. It shows that `signari serve` reads the environment, opens the
socket, unseals the client secret, runs the handshake, and looks the certificate
up in the database:

```
RESULT: Access-Accept
  User-Name from the certificate: probe2@example.test
  MPPE key attributes: 2
  TLS: TLS 1.3, cipher 0x1301
  MSK derived: 64 bytes
```

Each case gave this answer:

| | |
|---|---|
| valid certificate | Access-Accept, name from the certificate |
| account deactivated | **Access-Reject** + EAP-Failure |
| reactivated | Access-Accept |
| certificate from another CA | Access-Reject |
| wrong shared secret | **silence** — no answer at all |

The last one is the existing RADIUS behaviour, and worth keeping in view.
Answering would confirm that a RADIUS server is here, and turn the port into a
discovery tool.

## Partial configuration is fatal

If EAP-TLS is only partly configured, `signari serve` stops at startup with an
error such as this one:

```
signari: configuring EAP-TLS: SIGNARI_EAP_CLIENT_CA is required: without the
authorities that issue supplicant certificates there is nothing to verify one
against, and the handshake would admit anybody holding any certificate
```

It takes all three settings, or none. A server certificate without client
certificate authorities (CAs) would complete handshakes with anybody holding any
certificate. That is worse than no EAP-TLS at all, because it looks like it is
working.

## EAP-TTLS and PEAP: a password inside the tunnel

Some people have no certificate. For them, the supplicant can make a TLS tunnel to
Signari and check Signari's certificate. Then it sends the person's name and
password inside the tunnel. To turn this on, set the tunnel methods beside
Signari's certificate and key:

```sh
SIGNARI_EAP_TUNNELS=ttls,peap     # with SIGNARI_EAP_TLS_CERT and SIGNARI_EAP_TLS_KEY
```

With **EAP-TTLS** (RFC 5281), the name and password go as PAP AVPs, the
attribute-value pairs of the Password Authentication Protocol. With **PEAP**
(version 0, MS-PEAP), Signari asks for an identity, then for the password in an
EAP-GTC prompt. It says the result in a Result TLV.

Either way, the password is checked exactly as a PAP request's is: the same
account, status and lockout. The access point is given the tunnel's own keys, so
traffic flows once the person is in.

- **PEAP's inner method is EAP-GTC.** MSCHAPv2, the one Windows offers by itself,
  needs the password's NT hash, and nothing here keeps one. A peer that asks for
  MSCHAPv2 is refused. Windows needs a GTC module to use PEAP here. Most other
  supplicants offer GTC directly.
- **No PEAP cryptobinding.** MS-PEAP makes it optional. Without it, the keys are
  EAP-TLS's, as MS-PEAP specifies for that case.

- **Off unless set**. It is a password method, and the certificate is the only
  thing standing between a person's password and whoever answers in its place.
  A supplicant that is not set to check the certificate sends the password to
  anyone. Configure every supplicant with the issuing CA and Signari's server name.
- **Certificates first.** With EAP-TLS on as well (`SIGNARI_EAP_CLIENT_CA`),
  EAP-TLS is offered first. A supplicant without a certificate refuses it,
  naming the methods it would rather use. It is then offered the first of those
  that is on. With only `SIGNARI_EAP_TUNNELS`, PEAP is offered straight away if
  it is on, otherwise EAP-TTLS, and EAP-TLS stays off.
- **No resumption.** A resumed session skips the password entirely, so nothing
  is kept to resume. Every connection checks the password, and somebody
  deactivated since is refused at their next one.
- **TLS 1.2.** The tunnel's keys are defined over TLS 1.2. So the tunnel runs
  TLS 1.2, with the extended master secret, as Go requires for exporting keys.
- **A second factor.** PEAP asks for the code in a second GTC prompt, which is
  what GTC was made for. With EAP-TTLS, the code is typed after the password, as
  `password;123456`, as for PAP.

## Not implemented

- **Any other password method.** A supplicant that asks for EAP when none of
  EAP-TLS, EAP-TTLS and PEAP is on is **refused**, not offered something weaker.
- **CRL and OCSP checking.** The account-status check above covers the case that
  matters, somebody leaving, and does it faster than a revocation list
  propagates. A stolen laptop with a live account is a revocation problem, and
  that is the gap.
- **RADIUS accounting.** It is a separate protocol with separate risks.
