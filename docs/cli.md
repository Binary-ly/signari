# `signari` — command reference

> Related: [comparison-matrix.md](comparison-matrix.md) (how we compare, with
> evidence markers), [benchmarks.md](benchmarks.md) (measured numbers and method),
> [roadmap-standards.md](roadmap-standards.md) (what the working groups are doing).


Every command the binary dispatches. Kept complete by a test
(`TestEveryCommandIsDocumented`), because the usual failure is not a page that
rots — it is a command that ships and is never written down, which nobody finds,
because the person who added it knows it exists and everybody else cannot know
to look for it.

Most commands need `SIGNARI_DSN`. Anything touching sealed material also needs
`SIGNARI_ROOT_KEY`. See [configuration.md](configuration.md).

## Schema

| | |
|---|---|
| `signari migrate bootstrap` | Apply 0001 — roles, schemas, grants. Needs a **superuser** DSN |
| `signari migrate up` | Apply 0002+ as `signari_engine`. The ordinary upgrade step |
| `signari migrate all` | Bootstrap then up, in one invocation, for containers |
| `signari migrate status` | Applied version, pending migrations, live fingerprint |
| `signari verify` | Run the startup schema gate and exit. Use in a deploy pipeline |

The engine refuses to start when the database version and the binary disagree,
naming `migrate up` — a binary running against a schema it was not built for is
a class of failure that shows up as data corruption rather than an error.

## Running it

| | |
|---|---|
| `signari serve` | The engine. `-addr`, `-tls-cert`, `-tls-key` |
| `signari doctor` | Check a deployment's configuration and report what is wrong |
| `signari janitor once` | Run one janitor pass by hand — expiry, sweeping, parking |
| `signari plan` / `signari apply` | Declarative configuration from a file. `apply -prune` to delete what the file omits |

## Instances, organisations, users

| | |
|---|---|
| `signari instance create` | An issuer and its first signing keys |
| `signari user create` | A user with a password. Subject to the [password policy](password-policy.md) |
| `signari group create` / `group list` / `group member` / `group release` | Groups, membership, and which clients may see them |
| `signari invite create` / `invite list` | Invitations |
| `signari signup enable` / `signup disable` / `signup show` | Self-service sign-up, and which email domains may use it |
| `signari registration enable` / `registration token` | Dynamic client registration (RFC 7591) |
| `signari delete` | Erasure. Crypto-shredding, see [erasure.md](erasure.md) |

## Clients

| | |
|---|---|
| `signari client create` | Register an OAuth client |
| `signari client set-keys` | Switch to `private_key_jwt` with a public JWKS |
| `signari client set-tls` | mTLS client authentication and certificate-bound tokens |
| `signari client set-hybrid` | Permit hybrid response types |
| `signari client set-grants` | Which grant types this client may use (RFC 6749 §5.2) |

## Verifiable credentials

| | |
|---|---|
| `signari credential define` | Define a credential this issuer mints (SD-JWT VC) |
| `signari credential list` | Show the credential configurations published |
| `signari credential offer` | Mint an OID4VCI Credential Offer. See [oid4vci.md](oid4vci.md) |

## Keys and audit

| | |
|---|---|
| `signari keys list` / `keys rotate` | Signing keys; rotation is next → active → passive |
| `signari audit checkpoint` | Anchor the audit chain. See [audit-chain-fork.md](audit-chain-fork.md) |
| `signari export audit` | Export the trail |
| `signari admin-token create` / `admin-token list` / `admin-token revoke` | Admin API credentials |

## Federation in

| | |
|---|---|
| `signari idp add` / `idp list` | An upstream OIDC or OAuth provider |
| `signari idp apple-secret` | Mint the client secret Apple requires (a signed JWT that expires) |
| `signari google` / `signari entra` | Shorthands for the two most common ones |
| `signari saml add-sp` / `saml list` | SAML service providers |
| `signari scim-source add` / `scim-source list` | Inbound SCIM |
| `signari kerberos check` / `kerberos principals` / `kerberos sync` | Kerberos/SPNEGO, keytab checking, principal import |
| `signari dir add` / `dir sync` | Directory sync from LDAP, Entra or Google |
| `signari import keycloak` / `import authentik` | Migrate a realm or an installation in |

## Federation out

| | |
|---|---|
| `signari scim add` / `scim list` / `scim sync` / `scim verify` | Outbound SCIM provisioning |
| `signari provision add` | Provisioning targets |
| `signari ssf add-stream` / `ssf list` | Shared Signals (CAEP/RISC) streams |
| `signari events subscribe` / `events list` | Event subscriptions — see [events.md](events.md) |
| — | Transaction Tokens are issued at the token endpoint, not by a command — see [transaction-tokens.md](transaction-tokens.md) |

## Authorization

| | |
|---|---|
| `signari authz set-model` / `authz show-model` | The authorization model. Setting one **runs its own tests** — see [authorization.md](authorization.md) |
| `signari federation enable` / `federation show` | Join an OpenID Federation. Generates a **separate** Entity Statement signing key and publishes `/.well-known/openid-federation` — see [openid-federation.md](openid-federation.md) |
| `signari authz grant` / `authz revoke` | Relations: `-principal user:alice -relation owner -object document:42` |
| `signari authz check` | Answer a question from the command line, with the reason |

## Outposts and remote access

| | |
|---|---|
| `signari outpost create` / `outpost list` / `outpost run` | LDAP, RADIUS, proxy and desktop outposts |
| `signari ldap` / `signari radius` | Run those protocol servers |
| `signari radius add-client` / `radius list` / `radius enable-client` / `radius disable-client` | RADIUS clients and their shared secrets |
| `signari proxy check` | Check a forward-auth deployment **from outside** the network — which is why it dispatches before the database is required |
| `signari rac add` / `rac list` | Remote access connections |
| `signari rdp` / `signari vnc` / `signari ssh` | Start a remote session of that kind |

## Policy, prompts, branding

| | |
|---|---|
| `signari policy show` / `policy apply` / `policy test` / `policy graph` | Access policy. `policy test` answers "would this have been allowed" |
| `signari flow test` / `flow paths` / `flow show` | Sign-in flows. `flow test` refuses a file whose journeys could issue a session without proving the subject; `flow paths` lists every journey a flow admits; `flow show` prints the built-in flows as a file to start from. See [flows.md](flows.md) |
| `signari prompt list` / `prompt set` | Interstitial prompts — terms, notices |
| `signari brand set` / `brand show` / `brand check` | Branding. `brand check` verifies contrast |
| `signari duo set` / `duo enroll` / `duo show` | Duo as a second factor |
| `signari attester add` / `attester list` | Trusted Client Attesters for attestation-based client authentication. `attester add --org <id> --name <n> --attester-jwks <file>` registers an attester's **public** keys; a file containing private keys is refused, because this server could then forge the attestations it verifies. Nothing authenticates with `attest_jwt_client_auth` until at least one attester is registered |

## Testing

| | |
|---|---|
| `signari logout-test` | Prove back-channel logout actually terminates a relying party's session |
