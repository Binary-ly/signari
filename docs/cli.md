# `signari` — command reference

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
| `signari migrate fingerprint` | Print **only** the schema fingerprint, for pinning a release build. See [schema-pinning.md](schema-pinning.md) |
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
| `signari erase subject` | Crypto-shred a subject: destroy their data-encryption key so ciphertext, including in backups, is permanently unreadable. See [erasure.md](erasure.md) |

There is **no** `signari delete`. This page listed one for months; it has never
existed, and the test that exists to catch exactly that could not see this table
— see the note at the end of this page.

## Clients

| | |
|---|---|
| `signari client create` | Register an OAuth client |
| `signari client set-keys` | Switch to `private_key_jwt` with a public JWKS |
| `signari client set-tls` | mTLS client authentication and certificate-bound tokens |
| `signari client set-dpop` | RFC 9449 §5.2: require a DPoP proof on every token request from this client |
| `signari client set-exchange-containment` | RFC 8693: only exchange subject tokens this client holds or is named in the audience of |
| `signari client set-hybrid` | Permit hybrid response types |
| `signari client set-claims-redirects` | UMA 2.0 §3.3.2: where a requesting party may be returned after claims gathering. A separate list from `redirect_uris`, because the specification forbids reusing those. See [uma.md](uma.md) |
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
| `signari keys list` / `keys rotate` / `keys retire` | Signing keys; rotation is next → active → passive → retired. See [key-rotation.md](key-rotation.md) |
| `signari audit checkpoint` | Anchor the audit chain. See [audit-chain-fork.md](audit-chain-fork.md) |
| `signari export audit` | Export the trail |
| `signari admin-token create` / `admin-token list` / `admin-token revoke` | Admin API credentials |

## Federation in

| | |
|---|---|
| `signari idp add` / `idp list` | An upstream OIDC or OAuth provider |
| `signari idp assertions` | Allow or refuse RFC 7523 assertions from a provider. See [jwt-bearer.md](jwt-bearer.md) |
| `signari idp add-issuer` | Register a key-publishing issuer (GitHub Actions, Kubernetes) for the jwt-bearer grant |
| `signari client set-assertion-issuers` | Which issuers' assertions a client may exchange. Empty permits none. See [jwt-bearer.md](jwt-bearer.md) |
| `signari idp apple-secret` | Mint the client secret Apple requires (a signed JWT that expires) |
| `signari dir add -kind google` / `-kind entra` | Directory sync from the two most common sources. `google`, `entra` and `ldap` are values of `-kind`, not commands of their own |
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
| `signari trust-mark issue` / `trust-mark revoke` / `trust-mark list` | Issue, withdraw and inspect OpenID Federation Trust Marks. See [trust-marks.md](trust-marks.md) |
| `signari trust-mark accept` / `trust-mark drop` | Publish, or stop publishing, a Trust Mark somebody granted this entity |
| `signari trust-mark delegate` | Authorise another entity to issue a Trust Mark type this one owns (§7.2) |
| `signari trust-mark issuers` / `trust-mark owners` | The Trust Anchor's two governing claims. Refused from anything with a Superior, because every reader is required to ignore them there |
| `signari federation enable` / `federation show` | Join an OpenID Federation. Generates a **separate** Entity Statement signing key and publishes `/.well-known/openid-federation` — see [openid-federation.md](openid-federation.md) |
| `signari authz grant` / `authz revoke` | Relations: `-principal user:alice -relation owner -object document:42` |
| `signari authz check` | Answer a question from the command line, with the reason |
| `signari uma settings` | Offer, or stop offering, resource-owner intervention on refused UMA requests (§3.3.6 `request_submitted`). Off means a refusal is final. See [uma.md](uma.md) |
| `signari uma requests` / `uma approve` / `uma deny` | Requests waiting for a resource owner. Approving **grants a relation** in the authorization model, so the access lives where all other access lives |

## Outposts and remote access

| | |
|---|---|
| `signari outpost create` / `outpost list` / `outpost run` | LDAP, RADIUS, proxy and desktop outposts |
| — | LDAP and RADIUS are **listeners inside `signari serve`**, not commands. Set `SIGNARI_LDAP_ADDR` or `SIGNARI_RADIUS_ADDR`; each is off unless its address is. See [ldap.md](ldap.md) and [radius.md](radius.md) |
| `signari radius add-client` / `radius list` / `radius enable-client` / `radius disable-client` | RADIUS clients and their shared secrets |
| `signari proxy check` | Check a forward-auth deployment **from outside** the network — which is why it dispatches before the database is required |
| `signari rac add` / `rac list` | Remote access connections |
| `signari rac add -protocol rdp` / `vnc` / `ssh` | The protocol is a value of `-protocol`, not a command. Sessions are started from `/rac` in a browser |

## Policy, prompts, branding

| | |
|---|---|
| `signari policy show` / `policy apply` / `policy test` / `policy graph` | Access policy. `policy test` answers "would this have been allowed" |
| `signari flow test` / `flow paths` / `flow apply` / `flow show` | Sign-in flows. `flow test` refuses a file whose journeys could issue a session without proving the subject; `flow paths` lists every journey a flow admits; `flow apply` installs one for an organisation, printing every journey it admits; `flow show` prints the built-in flows as a file to start from. See [flows.md](flows.md) |
| `signari prompt list` / `prompt set` | Interstitial prompts — terms, notices |
| `signari brand set` / `brand show` / `brand check` | Branding. `brand check` verifies contrast |
| `signari duo set` / `duo enroll` / `duo show` | Duo as a second factor |
| `signari attester add` / `attester list` | Trusted Client Attesters for attestation-based client authentication. `attester add --org <id> --name <n> --attester-jwks <file>` registers an attester's **public** keys; a file containing private keys is refused, because this server could then forge the attestations it verifies. Nothing authenticates with `attest_jwt_client_auth` until at least one attester is registered |

## Testing

| | |
|---|---|
| `signari logout-test` | Prove back-channel logout actually terminates a relying party's session |

## Why this page was wrong

In August 2026 this table listed **eight** commands that do not exist:
`delete`, `google`, `entra`, `ldap`, `radius`, `rdp`, `vnc`, `ssh`. Seven of them
were argument *values* — `dir add -kind google`, `rac add -protocol rdp` — written
up as though they were commands. The eighth was never anything.

Two tests exist to prevent precisely this, and both missed it for the same
reason and a different one:

- `TestEveryDocumentedCommandExists` matched invocations **anchored at the start
  of a line**, so every row of this table — which begins `` | `signari … `` —
  was invisible to it. The page whose entire job is to list every command was the
  one page the check could not read.
- It also treated **every** `case "…"` in `main.go` as a command, including
  switches on unrelated strings. `case "delete":` belongs to an `-on-deactivate`
  flag, and that alone made `signari delete` look real.

Both are fixed. The lesson is the one this repository already had written down
about discovery documents, arriving somewhere new: a check that cannot see the
thing it is checking passes for the same reason a correct one does.
