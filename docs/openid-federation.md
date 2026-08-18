# OpenID Federation

Signari publishes an **Entity Configuration** — the self-signed Entity Statement
that makes it a member of an OpenID Federation.

Specification: OpenID Federation 1.0, **Final, 17 February 2026**.

## What is implemented, and what is not

**Implemented.** The Entity Configuration (§9): the statement an entity publishes
about itself at `/.well-known/openid-federation`. It is the leaf of every Trust
Chain and the prerequisite for everything else in the specification.

**Not implemented.** The federation endpoints of §8 — fetch, subordinate listing,
resolve, trust mark status — and trust-chain resolution. Signari can therefore be
a **Leaf Entity** in a federation. It cannot yet be an Intermediate or a Trust
Anchor for others, and it does not yet consume other entities' statements.

Nothing advertises what is missing. The `federation_entity` metadata contains no
`federation_fetch_endpoint`, because that endpoint does not exist — the same rule
this repository applies to OIDC discovery. A federation operator reading our
metadata will configure us as a Leaf, which is what we are.

## Enabling it

    signari federation enable \
      -authority-hints https://anchor.example \
      -organization-name "Example University"

Then restart `signari serve`; the endpoint is registered at startup only when a
federation key exists.

`-authority-hints` names this entity's **Immediate Superiors**. §3.1.2 makes it
REQUIRED for any entity with a superior above it, forbids the empty array, and
forbids the claim entirely for a Trust Anchor with no superiors. Omitting the
flag publishes this entity as a Trust Anchor, and the command says so rather than
leaving it to be inferred.

## The federation key is separate, and that is the point

§3.1.1, of the `jwks` claim:

> These Federation Entity Keys **SHOULD NOT** be used in other protocols. (Keys
> to be used in other protocols, such as OpenID Connect, are conveyed in the
> metadata elements for the protocol's Entity Type Identifiers...)

The easy implementation reuses the OIDC signing key: it is already loaded,
already wrapped, already published. It is also wrong. The two keys answer
different questions — a relying party trusts our OIDC key to assert *who a user
is*; a federation trusts our federation key to assert *what this entity is and
who vouches for it*. Rotating one should not rotate the other, and compromising
one should not forge the other.

So `core.signing_keys` gained a `purpose` column rather than federation keys
getting their own table: the rotation states, the root-key wrapping and the
retirement sweep are already correct there, and a second table would be a second
copy of them that eventually drifts.

Two things had to follow from that column, and only one was obvious:

- `LoadSet` now filters `purpose = 'oidc'`. Without it, generating a federation
  key would have silently published it at `/oauth2/jwks` — the exact conflation
  the separation exists to prevent, arriving as an accident rather than a
  decision.
- The `signing_keys_one_active` unique index had to become
  `(instance_id, purpose, algorithm)`. It was `(instance_id, algorithm)`, which
  is right for a table holding one kind of key; with two, an active ES256
  federation key collides with the active ES256 protocol key.

The second was **found by running the command**, not by reading the migration.
`signari federation enable` failed with a constraint violation on any instance
that already had OIDC keys — which is every instance. Migration 0075 fixes it,
and its comment says how it was found.

## Verified end to end

A fresh instance, federation enabled, `serve` restarted, then the endpoint
fetched and its signature checked against the key in its own `jwks`:

| Requirement | Spec | Observed |
|---|---|---|
| `typ` header | §3 | `entity-statement+jwt` |
| `kid` header | §3 (MUST) | present, and in the published `jwks` |
| `iss` == `sub` | §3.1.1 | both `https://idp.example` |
| `iat`, `exp` | §3.1.1 | 86400s lifetime |
| `jwks` | §3.1.1 | the federation key **only** |
| `authority_hints` non-empty | §3.1.2 | `["https://anchor.example"]` |
| `metadata` entity types | §5.1 | `federation_entity`, `openid_provider` |
| Content-Type | §15.1 | `application/entity-statement+jwt` |
| Signature | §3 | **verifies against the key in its own `jwks`** |

And the separation held: the OIDC JWKS served two kids, neither of them the
federation key's.

## Where it goes next

Trust-chain resolution — fetching a superior's Subordinate Statement about us,
and validating a chain from a leaf up to a Trust Anchor — is the next piece, and
it is what turns a published configuration into actual federated trust. The
`oidfed` package's `ValidateEntityID` and `ConfigurationURL` are already the
pieces a fetcher needs.
