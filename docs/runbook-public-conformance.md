# Exposing a deployment for OIDF conformance

## Introduction

The OpenID Foundation (OIDF) runs a conformance suite, which tests whether an
OpenID Connect (OIDC) provider follows the specifications. The suite is hosted,
at `https://certification.openid.net`, so it must reach Signari over public
HTTPS.

This runbook gives two ways to expose a deployment for a run, and the cheap one
is enough. Both use a Cloudflare tunnel, which carries public traffic to a port
on your own machine.

> [!NOTE]
> Run the preflight in `tools/conformance-preflight` against the public address
> before you start the suite. Its README lists the steps to certification.

## Cloudflare quick tunnel (no account, no server, ~30 seconds)

Start a quick tunnel to the port the engine will listen on. It prints a public
address:

```sh
cloudflared tunnel --url http://127.0.0.1:9411
#   -> https://<random-words>.trycloudflare.com
```

Then start the engine with that EXACT string as the issuer:

```sh
signari instance create -dsn "$SIGNARI_DSN" -issuer "https://<random>.trycloudflare.com"
SIGNARI_ISSUER="https://<random>.trycloudflare.com" signari serve -addr 127.0.0.1:9411
```

**The issuer must equal the public URL byte for byte.** Applications, which the
specifications call "relying parties", compare `iss` as an exact string, and so
does the conformance suite. A trailing slash, http instead of https, or a stale
hostname fails every check. The error names the token, not the configuration.

This was verified working:

```
issuer                : https://<random>.trycloudflare.com
jwks_uri              : https://<random>.trycloudflare.com/oauth2/jwks
JWKS over public TLS  : 200
```

### What a quick tunnel is not

* **Ephemeral.** The hostname dies with the process. That is fine for a
  conformance run, and useless for anything anyone must be able to find
  tomorrow.
* **Not a place to leave a development instance.** The address is unguessable,
  not private, and a development database has test accounts with known
  passwords. Start it for the run, and stop it after.

## Named tunnel on your own domain (stable, still no server)

A named tunnel gives a stable address on a domain you control. The first
command is interactive, so run it yourself:

```sh
cloudflared tunnel login            # interactive: run this yourself
cloudflared tunnel create signari
cloudflared tunnel route dns signari id-test.signari.dev
cloudflared tunnel run --url http://127.0.0.1:9411 signari
```

This gives a stable hostname and a real certificate, with no virtual private
server (VPS). It is the right shape for a demo instance that must keep working.

## When a VPS is actually the answer

Not for conformance, but for anything that must outlive the laptop: a
persistent demo, real people, the hosted tier.

Read the [backup and restore runbook](runbook-backup-restore.md),
`docs/runbook-backup-restore.md`, before putting real accounts on one. Note too
that the engine belongs on its own host, not beside anything that runs arbitrary
code.
