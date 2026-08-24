# Signari

A self-hosted identity provider. One binary and one PostgreSQL database serve
OpenID Connect, OAuth 2.0, SAML 2.0, LDAP, RADIUS and SCIM, with a web console
beside it.

> **Status: pre-release.** It runs, it is tested, and it is not yet certified.
> The OpenID Foundation conformance suite has a runbook here
> ([docs/runbook-public-conformance.md](docs/runbook-public-conformance.md)) but
> certification has not been obtained. Read
> [docs/security-review-asvs.md](docs/security-review-asvs.md) and
> [docs/fips.md](docs/fips.md) before trusting it with anything that matters.

## Two pieces, one database

**`engine/`** — Go. The protocol server, the `signari` operator CLI, and the
sign-in pages, which are server-rendered HTML with no JavaScript framework.

**`admin/`** — Laravel and Filament. The console.

They share one PostgreSQL database and are held apart by the database itself
rather than by convention. The engine owns schema `core`; the console has **no
privileges on it at all** and reads through versioned `core_v1` views, subject
to the same row-level security the engine is. Every console write goes over the
engine's Admin API. A `REVOKE` is one line and survives every future deadline;
a code-review rule does not.

## What it speaks

**OAuth 2.0 / OIDC** — authorization code with PKCE, refresh with rotation,
client credentials, device grant (RFC 8628), CIBA, token exchange (RFC 8693),
JWT bearer (RFC 7523), PAR (RFC 9126), DPoP (RFC 9449), rich authorization
requests (RFC 9396), mutual-TLS (RFC 8705), dynamic registration (RFC 7591),
introspection, revocation, and three logout mechanisms.

**Everything else an estate actually has** — SAML 2.0 in both directions,
WS-Federation, LDAP as a server and as a source, RADIUS with EAP-TLS,
Kerberos/SPNEGO, SCIM in both directions, OID4VCI credential issuance, OpenID
Federation, UMA 2.0, AuthZEN, and Shared Signals/CAEP.

## Three things that are different here

**Sign-in flows, access policy and configuration are files.** Not a graph
editor, not click-ops. They diff in a pull request, they carry their own tests,
and `signari flow test` and `signari policy test` run those tests in CI with no
database. `signari plan` shows what an apply would change before it changes it,
and absence never means deletion unless you ask for it.

**Security-negative decisions are never cached.** Client disabled, user
deactivated, session revoked, token revoked — all read from the database on the
request path. That is the failure class behind a long row of identity-provider
CVEs, and it is why there is no Redis here.

**It refuses to start rather than run wrong.** No root key, a schema the binary
was not built for, a signing key it cannot unwrap, an issuer that would publish
metadata it cannot honour — each is a startup failure with an actionable
message, not a warning nobody reads. `signari doctor` reports the rest.

## Quick start

```sh
createdb signari_dev
export SIGNARI_DSN=postgres://localhost/signari_dev
export SIGNARI_ROOT_KEY=$(head -c 32 /dev/urandom | base64)

cd engine
go build -o signari ./cmd/signari
./signari migrate all                      # roles, schemas, tables, policies
./signari instance create -issuer http://localhost:8080
./signari serve -addr 127.0.0.1:8080
```

`SIGNARI_ROOT_KEY` seals every stored secret and is not kept in the database it
protects. Lose it and the sealed data — signing keys, bind passwords, RADIUS
secrets — cannot be recovered. See
[docs/configuration.md](docs/configuration.md) for every setting and
[docs/runbook-backup-restore.md](docs/runbook-backup-restore.md) for why a
database backup alone is worthless.

For the console, see [admin/README.md](admin/README.md). For Kubernetes, see
[deploy/helm/signari/README.md](deploy/helm/signari/README.md).

## Documentation

**[docs/README.md](docs/README.md)** indexes all ninety-odd pages by task.
The three you will reach for first:

| | |
|---|---|
| [docs/configuration.md](docs/configuration.md) | Every environment variable |
| [docs/cli.md](docs/cli.md) | Every command |
| [docs/doctor.md](docs/doctor.md) | Whether this deployment is sound |

Those three cannot rot: the engine's `internal/docsync` package fails the build
when a command or a setting exists in code and not on its page.

## Licence

[AGPL-3.0-only](LICENSE). Running Signari does not make your applications AGPL —
talking to it over OIDC is use, not derivation, the same way running PostgreSQL
does not license your schema. The obligation applies to modifying Signari itself
and offering that modified version to others over a network. See
[NOTICE.md](NOTICE.md), which also covers commercial licensing and the
contribution terms that make it possible.
