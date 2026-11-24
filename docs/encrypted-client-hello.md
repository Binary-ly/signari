# Encrypted Client Hello

## Introduction

A Transport Layer Security (TLS) handshake starts with the name the client wants,
in the clear (see [TLS](glossary.md#tls)). For an identity provider, that name
tells anyone on the path which organisation somebody is signing in to.

With Encrypted Client Hello (ECH, RFC 9849), the client encrypts the name to a key
Signari published. It sends a shared *public name* in the clear in its place. It
is requirement V12.1.5 of the Application Security Verification Standard (ASVS)
5.0.0, a level 3 requirement.

You make keys with `signari ech new`, and load them with `SIGNARI_TLS_ECH_KEYS`.

## Turning it on

The public listener takes ECH when it has keys. Make a key, then start the engine
with it:

```sh
signari ech new -public-name front.example.com -out /etc/signari/ech-2026-11.pem
SIGNARI_TLS_ECH_KEYS=/etc/signari/ech-2026-11.pem signari serve -tls-cert … -tls-key …
```

`ech new` writes the key to a new file only, never over one that exists, and
prints the configuration to publish.

Clients learn it from the "HTTPS record" of the name people sign in at. That is a
record in the Domain Name System (DNS), described in RFC 9848. It goes there as
`ech=` and Base 64:

```
auth.example.com. 300 IN HTTPS 1 . ech="AEb+DQBCAgAg…"
```

The engine logs the same value as `ech_config_list` when it starts.

## What it costs

- **TLS 1.3 only.** ECH is a TLS 1.3 mechanism, and the listener with keys takes
  nothing older. A TLS 1.2 client is refused with `protocol_version`.
- **A certificate for the public name too.** A client whose configuration Signari
  no longer holds is refused ECH. It checks the handshake against the public name,
  which it reads from the configuration (RFC 9849 §6.1.7). It is then handed the
  current configuration to retry with.
- **It hides the name only among others.** The public name is what an observer
  sees. So it hides something only when several names share it, behind one front,
  as on a content delivery network (CDN). A deployment whose only name is its own
  public name gains nothing. The address the client connects to is not hidden
  either.

## Changing keys

Clients cache a DNS answer for its time to live (TTL), and longer. So a key stays
loaded after its successor is published. Make the new key, publish it, and then
load both, newest first:

```sh
signari ech new -public-name front.example.com -out /etc/signari/ech-2026-12.pem
# publish its ech= value, then:
SIGNARI_TLS_ECH_KEYS=/etc/signari/ech-2026-12.pem,/etc/signari/ech-2026-11.pem
```

The first file is the one a refused client is told to retry with. The rest are
accepted and not handed out.

Each key has a config ID, random unless `-config-id` is given. That ID is how a
client says which key it used. So two keys loaded together with one ID are
refused.

So is a file whose configuration is not its own key's, and so are keys set for a
listener with no certificate. In each case the engine does not start, rather than
starting with the name in the clear.

## Measured

This was measured in November 2026, with the engine holding two keys, and a
client that read the ClientHello off the wire through a relay:

| Client's configuration | On the wire | The server saw | Result |
|---|---|---|---|
| The published key's | the public name | the real name | ECH accepted, TLS 1.3, discovery 200 |
| The previous key's | the public name | the real name | ECH accepted |
| A key the server does not hold | the public name | — | refused, retry configuration offered: exactly the published one |
| TLS 1.2, no ECH | the real name | — | `protocol version not supported` |

The configuration encoder reads and writes RFC 9848's own example (Figure 1) byte
for byte. So a key from here is one any ECH client can use, not only Go's.
