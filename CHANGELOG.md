# Changelog

Each release, what it changes and what an operator should know before upgrading to it.
Versions are `vMAJOR.MINOR.PATCH`; before 1.0, a minor version may change behaviour,
and its entry says how.

## Unreleased

- **Releases are signed.** `.github/workflows/release.yml` rebuilds each published
  release from its tag and, only if the binary comes out byte-identical, signs the
  binary and its SBOM with cosign and records SLSA build provenance. v0.1.0 was
  signed this way after its release; `SECURITY.md` says how to check a download.
- The SBOM no longer records the hashes of the SBOM tool's own executable, which
  differed with wherever the tool was installed, so it is the same on any machine.
- The release's provenance is attached beside the binary as `.intoto.jsonl`.
- **Dependencies.** go-jose 4.1.9, `golang.org/x/crypto` 0.59.0, `x/net` 0.63.0 and
  `x/sys` 0.50.0, past published advisories, none of which `govulncheck` found
  reachable. The workflows' actions are pinned by commit, the Node examples install
  from a lockfile with `npm ci`, and the Django example's requirements carry hashes.
  Dependabot proposes updates weekly.
- A batch's walks take their first level from the rows of the step they share, so a
  hundred documents in one deep folder cost that step and one walk up the folders:
  46 to 162 batches a second at one client.
- **A CLI write and an Admin API write at once no longer deadlock.** The operator CLI
  took the configuration version's row after the rows it wrote; the Admin API,
  `signari apply` and an SSF receiver changing its stream take it before. So a
  command and an API write to the same client, provider or organisation, or adding
  two people to one organisation, could each hold what the other waited for, and
  PostgreSQL ended one of them a second later: a 500 from the API, or a failed
  command. Every CLI write now takes the version's row first. Migration 0307 runs
  the version's trigger before each statement rather than after it, and in a CLI
  session the audit trail's append takes the row before its own lock. The commands
  that lock a row by reading it before they write take the row themselves.
- Migration 0307 is not compatible with the release before, since it changes the
  triggers on tables that release writes: stop it before migrating, as
  `docs/schema-versions.md` says, and keep the backup `docs/upgrading.md` asks for,
  which is the way back.
- An SSF verification refused for coming too soon says in `Retry-After` how long its
  window has left, not the whole 30 seconds, and `docs/ssf-caep.md` says how the
  windows fall.

## v0.1.0 — 2026-11-22

The first public release.

### What is in it

- **One Go binary and one PostgreSQL database.** The engine serves the protocols, the
  sign-in pages and the Admin API, and carries the `signari` operator CLI. The console
  (`admin/`, Laravel) reads the engine's data through versioned views and writes only
  through the Admin API; the database's own grants keep the two apart.
- **OAuth 2.0 and OpenID Connect:** authorization code with PKCE, refresh token
  rotation, client credentials, the device grant (RFC 8628), CIBA, token exchange
  (RFC 8693), JWT bearer (RFC 7523), PAR (RFC 9126), DPoP (RFC 9449), rich
  authorization requests (RFC 9396), mutual TLS (RFC 8705), dynamic registration
  (RFC 7591), introspection, revocation, and RP-initiated, front-channel and
  back-channel logout.
- **The rest of an estate:** SAML 2.0 in both directions, WS-Federation, LDAP as a
  server and as a source, RADIUS with EAP-TLS, Kerberos/SPNEGO, SCIM in both
  directions, OID4VCI credential issuance, OpenID Federation, UMA 2.0, AuthZEN and
  Shared Signals/CAEP.
- **Configuration as files:** sign-in flows, access policy and configuration are files
  with their own tests (`signari flow test`, `signari policy test`), planned before they
  are applied (`signari plan`).
- **Integrations:** a Terraform provider, a Kubernetes operator, Go and TypeScript
  clients of the Admin API, and a Helm chart.

### Conformance

Every OpenID Foundation conformance plan this release targets was run whole, from a
fresh clone, with no failed condition: Config, Basic and Form Post OP; RP-Initiated,
Front-Channel and Back-Channel Logout; FAPI 2.0 Security Profile (private_key_jwt with
DPoP, and both mutual-TLS variants) and Message Signing; the OID4VCI issuer plans; and
four OID4VP verifier plans. The results are in
[deploy/conformance/README.md](deploy/conformance/README.md). Two plans cannot pass by
design: Hybrid's `code token` and `code id_token token` and the Dynamic OP plan, since
the provider never puts an access token in the front channel.

### Security

- No publicly known vulnerability is fixed in this release; there are no earlier
  releases to have had one.
- Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes.
- Release builds are reproducible (built twice and compared byte for byte) and come with
  CycloneDX SBOMs for the binary and the image. Release artefacts are not yet signed.
- Not yet independently audited.

### Requirements

PostgreSQL 17, the version the compose file, the Helm chart and the test suite use, and
Go 1.26.11 or later to build from source. The README's quick start runs it;
[docs/upgrading.md](docs/upgrading.md) covers moving to later releases.
