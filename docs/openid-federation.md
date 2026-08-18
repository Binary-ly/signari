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

## Trust Chain validation

`oidfed.ValidateChain` implements §10.2's nine steps. A chain is an ordered list
of Entity Statements from the subject up to a Trust Anchor; validating it is what
turns "this server published a statement about itself" into "an authority I
already trust vouches for this server".

### The step that is easy to get backwards

§10.2 verifies ES[0] — the subject's own Entity Configuration — **twice**, and
the two checks do entirely different work:

> For ES[0] ... verify that its signature validates with a public key in
> ES[0]["jwks"].

> For each j = 0,...,i-1, verify that the signature of ES[j] validates with a
> public key in ES[j+1]["jwks"].

The first is a **self-signature**. It proves internal consistency and proves
nothing about trust, because anybody can sign a statement with a key they also
published inside it. An implementation that does only this has built a validator
that accepts every entity.

The second is where trust actually flows. ES[1] is the Subordinate Statement
issued by the superior *about* this entity, and its `jwks` is the key set the
superior attests the subordinate has. So checking ES[0]'s signature against
ES[1]'s `jwks` asks the only question that matters: **does the key this entity
signed with match the key its superior says it has?**

`TestALeafSignedWithAKeyItsSuperiorDoesNotAttestIsRefused` is that scenario
directly — a leaf rotates to a key its intermediate has never seen and re-signs
its own configuration. Self-consistent, unvouched-for, and refused.

### Two things the caller must supply out of band

`ValidateChain(chain, trustAnchorID, trustAnchorKeys, now)` takes the anchor's
identifier *and* its keys from the caller, never from the chain. §10.2's last two
steps are "verify that the issuer matches the Entity Identifier of the Trust
Anchor" and "verify that its signature validates with a public key of the Trust
Anchor" — and reading either from the chain makes the step verify the chain
against itself. A chain that names its own anchor validates for anybody.

### Chain expiry

§10.4: "The expiration time of the whole Trust Chain is the minimum (exp) value
within the Trust Chain." Taking the last statement's, or the subject's, would let
one long-lived member extend the life of a chain whose weakest link has already
gone stale.

### Mutation-tested

| Mutation | Test that caught it |
|---|---|
| Drop step 7 — verify only the self-signature | `TestALeafSignedWithAKeyItsSuperiorDoesNotAttestIsRefused` |
| Take the anchor's keys from the chain | `TestAValidChainValidates` |
| Chain expiry from the last member rather than the minimum | `TestTheChainExpiresWhenItsEarliestMemberDoes` |

Also refused: a broken link (`ES[j].iss != ES[j+1].sub`), an expired member, a
chain of one, a statement with no `kid` header (§3 makes it a MUST — without it a
verifier must try every key, which turns "signed by the attested key" into
"signed by any key in a set we were handed"), and any symmetric signing
algorithm.

## Fetching

`oidfed.Fetcher` retrieves Entity Configurations (§9) and Subordinate Statements
(§8.1).

### It walks a graph an attacker partly controls

This is the part worth being careful about. We fetch an entity's configuration,
read `authority_hints` **out of it**, and fetch those — so every URL after the
first is one the previous document chose. `authority_hints` is a list of
addresses somebody else writes, and following it is a server-side request forgery
primitive by construction.

So the fetcher uses `safedial`, which checks at **dial** time rather than at
parse time. A hostname that resolves publicly when validated and to
`169.254.169.254` when connected is DNS rebinding, and no amount of URL
inspection catches it. `TestTheDefaultFetcherRefusesPrivateAddresses` pins the
default: loopback, link-local and RFC 1918 are refused by a `Fetcher{}` with no
options set.

The escape hatch for tests is called `AllowLoopbackForTesting`, and the length of
that name is deliberate — a field called `Insecure` or `SkipVerify` gets set in a
config file by somebody solving a different problem. A test asserts the name has
not been shortened.

### What it refuses beyond addresses

| Refusal | Why |
|---|---|
| A configuration whose `iss` is not the entity we asked about | otherwise a superior hands back somebody else's configuration and we walk *their* `authority_hints` |
| A configuration where `iss != sub` | §3.1.1 — that is not an Entity Configuration |
| A Subordinate Statement about a different subject than we asked | how a chain gets rerouted to an entity nobody enquired about |
| A non-https fetch endpoint or subject identifier | §9 |
| A body over 256 KiB | bounded **before** it is read; a limit applied after buffering is not a limit |
| `authority_hints: []` | §3.1.2 forbids the empty array, and reading it as "no superiors" silently accepts a document saying something it may not say |

`MaxChainDepth` bounds the walk at 10. §6.2.1 lets a Trust Anchor impose a
`max_path_length` on its subtree; this is the local ceiling for when nobody has,
because a cycle of entities naming each other as superiors is otherwise walked
forever.

### ParseStatement verifies nothing, and says so

Parsing and verifying are necessarily separate here: a statement's signing key is
only known once the chain is assembled, so the fetcher cannot verify what it
retrieves. `ParseStatement` is named to make that unmistakable, and
`TestParseStatementVerifiesNothing` asserts that a corrupted signature still
*parses* — so that if somebody later adds verification there, the test tells them
callers may have started trusting its output.

## Where it goes next

The remaining pieces are the §8 endpoints we would serve as an Intermediate or
Trust Anchor (fetch, subordinate listing, resolve), and automatic client
registration (§12.1). Chain building — the loop that assembles a chain from
`authority_hints` using the fetcher and hands it to `ValidateChain` — is a short
step now that both halves exist, but it is not written yet and nothing pretends
otherwise.
