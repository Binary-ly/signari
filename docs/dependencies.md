# Third-party dependencies

OWASP ASVS 5.0.0 **V15.1.2** asks for "an inventory catalog, such as a software
bill of materials (SBOM)... including verifying that components come from
pre-defined, trusted, and continually maintained repositories", and **V15.1.1**
for "risk based remediation time frames".

`docs/security-scanning.md` covers the scanners. This covers what is being
scanned, and why each thing is here at all.

## The number is the point

**Thirteen direct dependencies. Fifty-seven modules in the whole graph.**

That is small for an identity provider, and it is the result of decisions rather
than luck: the QR encoder, the ASN.1/LDAP server, the Guacamole protocol codec,
the SD-JWT implementation, the RADIUS server and the flow language are all
written here rather than pulled in. Every dependency is a party that can change
what this binary does.

## Direct dependencies

| Module | Version | What it does | Why it is trusted |
|---|---|---|---|
| `github.com/go-jose/go-jose/v4` | v4.1.4 | JOSE: JWS, JWE, JWK | the reference Go JOSE library, maintained by the go-jose org after the Square handover; the crypto this whole product rests on |
| `github.com/jackc/pgx/v5` | v5.10.0 | PostgreSQL driver | the de-facto Go Postgres driver; parameterized queries are its default idiom |
| `github.com/go-webauthn/webauthn` | v0.17.4 | WebAuthn ceremonies | the maintained successor to duo-labs/webauthn |
| `github.com/beevik/etree` | v1.7.0 | XML tree, for SAML | used only after `scanForUnsafeConstructs` has refused DOCTYPE and comments |
| `github.com/russellhaering/goxmldsig` | v1.6.1 | XML signatures | the standard Go XML-DSig implementation |
| `github.com/go-ldap/ldap/v3` | v3.4.14 | LDAP **client**, for directory sync | our LDAP *server* is written here; this is only the outbound side |
| `github.com/go-asn1-ber/asn1-ber` | v1.5.8 | BER encoding | transitive requirement of the LDAP client, also used by our server |
| `github.com/jcmturner/gokrb5/v8` | v8.4.4 | Kerberos / SPNEGO | the only maintained pure-Go Kerberos implementation |
| `github.com/jcmturner/goidentity/v6` | v6.0.1 | identity type used by gokrb5 | comes with the above |
| `github.com/coder/websocket` | v1.8.15 | WebSocket, for remote access | the maintained successor to nhooyr.io/websocket; its `authenticateOrigin` is load-bearing for us (see the V4 review) |
| `golang.org/x/crypto` | v0.54.0 | Argon2id, HKDF, bcrypt | Go project |
| `golang.org/x/text` | v0.40.0 | Unicode normalisation | Go project; NFKC on passwords per NIST |
| `gopkg.in/yaml.v3` | v3.0.1 | configuration and flow files | operator-supplied input only, never a request |

## How provenance is verified (V15.2.4, dependency confusion)

Every module resolves through the public Go module proxy and is checked against
the public checksum database. `go.sum` pins a cryptographic hash for **every**
module in the graph, direct and transitive, and a mismatch fails the build rather
than warning.

There is **no `GOPRIVATE` and no `replace` directive**, so nothing resolves from
a private or substitutable source — which is the condition a dependency-confusion
attack needs. This is the rare requirement where Go's toolchain does the work and
the correct action is to not undermine it.

## Remediation time frames (V15.1.1)

Stated here because ASVS asks for them and because "we patch when we notice" is
not a policy:

| Severity of a finding against a dependency we use | Act within |
|---|---|
| Actively exploited, or a remote pre-auth path in a reachable code path | same day |
| High, reachable | 7 days |
| High, not reachable (`govulncheck` reports the module but not a called symbol) | 30 days |
| Medium or low | next routine update |
| No finding | review the graph quarterly regardless |

**Reachability is the discriminator, and `govulncheck` supplies it** — it reports
whether a vulnerable *symbol* is actually called, not merely whether a vulnerable
module is present. The distinction is what keeps the first row from becoming
every row.

## Risky components (V15.1.4) and dangerous functionality (V15.1.5)

Named rather than left implicit. These are the places where a dependency failure
or our own code has the widest blast radius:

- **`go-jose`** — every token this server issues and verifies. A flaw here is a
  full authentication bypass. It is also the dependency most likely to have one,
  because JOSE is the part of this stack with the worst historical record.
- **`etree` + `goxmldsig`** — SAML. The attack classes (wrapping, XXE, key
  confusion) are the reason `internal/saml/decode.go` refuses constructs *before*
  either library sees the document rather than trusting their configuration.
- **`gokrb5`** — parses attacker-supplied tickets from the network.
- **`internal/radius`** — parses UDP packets from the network, written here.
- **`internal/ldapd`** — parses BER from the network, written here.

The last two are ours, which is the point of listing them beside the others: the
risk is the parsing of hostile input, not who wrote it.

## Regenerating an SBOM

This document is the inventory. A machine-readable SBOM is generated rather than
checked in, because one that is checked in is one that is stale:

```sh
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
cyclonedx-gomod mod -json -output sbom.json ./engine
```

`go list -m all` is the same information without the tool.
