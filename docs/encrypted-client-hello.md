# Encrypted Client Hello

A TLS handshake starts with the name the client wants, in the clear. For an
identity provider that name says which organisation somebody is signing in to,
to anyone on the path. With Encrypted Client Hello (ECH, RFC 9849) the client
encrypts the name to a key the server published, and sends a shared *public name*
in the clear in its place. It is ASVS 5.0.0 V12.1.5, a level 3 requirement.

The public listener takes it when it has keys:

```sh
signari ech new -public-name front.example.com -out /etc/signari/ech-2026-11.pem
SIGNARI_TLS_ECH_KEYS=/etc/signari/ech-2026-11.pem signari serve -tls-cert … -tls-key …
```

`ech new` writes the key to a new file only, never over one that exists, and
prints the configuration to publish. Clients learn it from the HTTPS record of the
name people sign in at (RFC 9848), as `ech=` and Base 64:

```
auth.example.com. 300 IN HTTPS 1 . ech="AEb+DQBCAgAg…"
```

The engine logs the same value as `ech_config_list` when it starts.

## What it costs

- **TLS 1.3 only.** ECH is a TLS 1.3 mechanism, and the listener with keys takes
  nothing older. A TLS 1.2 client is refused with `protocol_version`.
- **A certificate for the public name too.** A client whose configuration the
  server no longer holds is refused ECH. It checks the handshake against the
  public name, which it reads from the configuration (RFC 9849 §6.1.7), and is
  handed the current configuration to retry with.
- **It hides the name only among others.** The public name is what an observer
  sees, so it hides something only when several names share it, behind one front,
  as on a CDN. A deployment whose only name is its own public name gains nothing.
  The address the client connects to is not hidden either.

## Changing keys

Clients cache a DNS answer for its TTL and longer, so a key stays loaded after
its successor is published:

```sh
signari ech new -public-name front.example.com -out /etc/signari/ech-2026-12.pem
# publish its ech= value, then:
SIGNARI_TLS_ECH_KEYS=/etc/signari/ech-2026-12.pem,/etc/signari/ech-2026-11.pem
```

The first file is the one a refused client is told to retry with. The rest are
accepted and not handed out. Each key has a config id, random unless
`-config-id` is given, which is how a client says which key it used, so two keys
loaded together with one id are refused. So is a file whose configuration is not
its own key's, and so are keys set for a listener with no certificate. In each
case the engine does not start, rather than starting with the name in the clear.

## Measured

November 2026, the engine with two keys and a client that read the ClientHello off
the wire through a relay:

| Client's configuration | On the wire | The server saw | Result |
|---|---|---|---|
| The published key's | the public name | the real name | ECH accepted, TLS 1.3, discovery 200 |
| The previous key's | the public name | the real name | ECH accepted |
| A key the server does not hold | the public name | — | refused, retry configuration offered: exactly the published one |
| TLS 1.2, no ECH | the real name | — | `protocol version not supported` |

The configuration encoder reads and writes RFC 9848's own example (Figure 1) byte
for byte, so a key from here is one any ECH client can use, not just Go's.
