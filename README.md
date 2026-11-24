# Signari

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16996/badge)](https://www.bestpractices.dev/projects/16996)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Binary-ly/signari/badge)](https://scorecard.dev/viewer/?uri=github.com/Binary-ly/signari)

A self-hosted identity provider. One binary and one PostgreSQL database serve
OpenID Connect, OAuth 2.0, SAML 2.0, LDAP, RADIUS and SCIM, with a web console
beside it.

> **Status: v0.1.0, the first release.** It runs, it is tested, and it is neither
> certified nor independently audited yet. The OpenID Foundation's conformance plans
> run whole in CI (`.github/workflows/conformance.yml`) and the suite has a runbook
> here ([exposing a deployment for conformance](docs/runbook-public-conformance.md)),
> but certification has not been obtained. Read the
> [OWASP ASVS 5.0 review](docs/security-review-asvs.md) and the
> [FIPS 140-3 notes](docs/fips.md) before trusting it with anything that matters.

## Two pieces, one database

**`engine/`** — Go. The protocol server, the `signari` operator CLI, and the
sign-in pages, which are server-rendered HTML with no JavaScript framework.

**`admin/`** — Laravel and Filament. The console.

They share one PostgreSQL database and are held apart by the database itself
rather than by convention. The engine owns schema `core`; the console has **no
privileges on it at all** and reads through versioned `core_v1` views, where
row-level security returns only the rows of the organisation a request has
chosen. The engine's own role, `signari_engine`, is the one those policies let
see every organisation. Every console write goes over the engine's Admin API. A
`REVOKE` is one line and survives every future deadline; a code-review rule
does not.

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

On a Linux server with PostgreSQL 16 or newer:

```sh
curl -fsSL https://raw.githubusercontent.com/Binary-ly/signari/main/scripts/install.sh | sh
```

The script downloads the release and installs it only if it matches the
release's SHA-256 sums and, when `cosign` is installed, its Sigstore signature.
Then `signari setup` asks what it cannot work out for itself: the address people
will reach Signari at, the first administrator's email, and which PostgreSQL to
use. It prints its plan before it changes anything, and ends with a one-time link
for that administrator and where it put the root key. To give the answers up
front and be asked nothing:

```sh
curl -fsSL https://raw.githubusercontent.com/Binary-ly/signari/main/scripts/install.sh | sh -s -- --yes --issuer https://login.example.com --email you@example.com
```

> [!NOTE]
> `signari setup` comes in the release after v0.1.0. Until that release is out,
> the script installs v0.1.0 and points you at that release's own setup steps. To
> use `signari setup` today, build `main` [from source](docs/installation.md#from-source).

To read the script first, download it with
`curl -fsSL https://raw.githubusercontent.com/Binary-ly/signari/main/scripts/install.sh -o install.sh`,
and `sh install.sh --dry-run` prints every command it would run. Its second line
is `# signari-install-script`, so a page that lacks that line is not the script.
Running either again is safe: a step already done is skipped, and
`signari setup -check` says what is set up and what is missing. The engine serves
as `signari_engine`, with a password setup generates, and never as a superuser,
whose powers over the database server the engine never needs.

### With Docker

v0.1.0 ships a binary for Linux on amd64 alone. Elsewhere, or with Docker to
hand, the compose stack runs the engine, its database and an application to sign
in to:

```sh
git clone https://github.com/Binary-ly/signari && cd signari/deploy
export SIGNARI_ROOT_KEY=$(head -c 32 /dev/urandom | base64) SIGNARI_FIRST_EMAIL=you@example.com \
  SIGNARI_TLS_CERT=/tls/engine.crt SIGNARI_TLS_KEY=/tls/engine.key
docker compose --profile first-run --profile demo up -d
docker compose logs bootstrap     # the one-time link
```

Open the link, set a password, and sign in at `http://localhost:8097/login`. The same
profile runs the Express, Next.js, Django, Spring Boot and Laravel quickstarts on ports
8091 to 8095; each guide's "In compose" section says which. The demo applications use
host networking, which Docker Desktop has from version 4.34 once "Enable host
networking" is turned on under Settings, Resources, Network. The certificate under
`deploy/tls` is for development and signed by a CA nobody else trusts. A data volume
made before the engine served as `signari_engine` needs that role's password set once,
as the [script that makes the role](deploy/postgres-init/20-engine-role.sh) says.

### From source

```sh
git clone https://github.com/Binary-ly/signari && cd signari/engine
go build -o signari ./cmd/signari
./signari setup
```

The root key seals every stored secret and is not kept in the database it
protects. Lose it and the sealed data — signing keys, bind passwords, RADIUS
secrets — cannot be recovered, so copy it off the machine once setup has made
it. See [the configuration reference](docs/configuration.md) for every setting and
[Backup and restore](docs/runbook-backup-restore.md) for why a
database backup alone is worthless.

For the console, see [the console's guide](admin/README.md). For Kubernetes, see
the [Helm chart](deploy/helm/signari/README.md).

## Documentation

**[The documentation home](docs/README.md)** indexes all ninety-odd pages by task.
The three you will reach for first:

| | |
|---|---|
| [Configuration](docs/configuration.md) | Every environment variable |
| [Command reference](docs/cli.md) | Every command |
| [Doctor](docs/doctor.md) | Whether this deployment is sound |

Those three cannot rot: the engine's `internal/docsync` package fails the build
when a command or a setting exists in code and not on its page.

## Contributing

Issues and pull requests are welcome. The [contributing guide](CONTRIBUTING.md) says what a
pull request needs and how a first contribution signs the Contributor License
Agreement; vulnerabilities go privately, as the [security policy](SECURITY.md) explains.

## Licence

[AGPL-3.0-only](LICENSE). Running Signari does not make your applications AGPL —
talking to it over OIDC is use, not derivation, the same way running PostgreSQL
does not license your schema. The obligation applies to modifying Signari itself
and offering that modified version to others over a network. See
the [licensing notice](NOTICE.md), which also covers commercial licensing and the
contribution terms that make it possible.
