# Exposing a deployment for OIDF conformance

The conformance suite must reach the server over public HTTPS. Two ways, and the
cheap one is enough.

## Cloudflare quick tunnel (no account, no server, ~30 seconds)

```sh
cloudflared tunnel --url http://127.0.0.1:9411
#   -> https://<random-words>.trycloudflare.com
```

Then start the engine with that EXACT string as the issuer:

```sh
signari instance create -dsn "$SIGNARI_DSN" -issuer "https://<random>.trycloudflare.com"
SIGNARI_ISSUER="https://<random>.trycloudflare.com" signari serve -addr 127.0.0.1:9411
```

**The issuer must equal the public URL byte for byte.** Relying parties -- and the
conformance suite -- compare `iss` as an exact string. A trailing slash, http
instead of https, or a stale hostname fails every check with an error that names
the token rather than the configuration.

Verified working:

```
issuer                : https://<random>.trycloudflare.com
jwks_uri              : https://<random>.trycloudflare.com/oauth2/jwks
JWKS over public TLS  : 200
```

### What a quick tunnel is not

* **Ephemeral.** The hostname dies with the process. Fine for a conformance run,
  useless for anything anyone must be able to find tomorrow.
* **Not a place to leave a development instance.** The URL is unguessable, not
  private, and a dev database has test accounts with known passwords. Start it
  for the run, stop it after.

## Named tunnel on your own domain (stable, still no server)

```sh
cloudflared tunnel login            # interactive: run this yourself
cloudflared tunnel create signari
cloudflared tunnel route dns signari id-test.signari.dev
cloudflared tunnel run --url http://127.0.0.1:9411 signari
```

Stable hostname, real certificate, no VPS. This is the right shape for a demo
instance that must keep working.

## When a VPS is actually the answer

Not for conformance -- for anything that must outlive the laptop: a persistent
demo, real users, the hosted tier. See `docs/runbook-backup-restore.md` before
putting real accounts on one, and note that the engine belongs on its own host
rather than beside anything that executes arbitrary code.
