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

## Chain building

`oidfed.Resolver` joins the two halves: it walks up from an entity using
`authority_hints`, fetching each superior's Entity Configuration and its
Subordinate Statement about the entity below, then hands the assembled chain to
`ValidateChain`.

### Why building and validating are separate passes

It is tempting to verify each statement as it arrives and fail fast. That cannot
work. §10.2 verifies ES[j] against **ES[j+1]**'s key set, so no statement can be
checked until the one *above* it has been fetched. A resolver that validates
incrementally is either doing it wrong, or checking each statement against its own
keys — which is the self-signature that proves nothing.

So the whole candidate chain is fetched, then validated. The cost is fetching
statements a later failure discards; the alternative is a validator that accepts
anybody.

### What it refuses

| Refusal | Why |
|---|---|
| No trust anchors configured | a chain that terminates nowhere trusted is not a result, it is a misconfiguration |
| A cycle in the federation graph | reported **as a cycle**, not as exhausting the depth budget — the error should name the fault, not the symptom |
| More than `MaxChainDepth` hops | the ceiling for when no Trust Anchor has imposed a `max_path_length` (§6.2.1) |
| A superior publishing no `federation_fetch_endpoint` | it cannot be asked about its subordinates, and the error says so rather than surfacing a transport failure |

§10.3's rule — *"prefer a shorter chain over a longer one"* — is implemented, and
shorter is preferred for a reason worth stating: each additional Intermediate is
another party who can vouch for something, so the shortest chain is the one with
the fewest entities able to change the answer.

### A mutation that survived, and what it revealed

Inverting the shortest-chain comparison to prefer the **longest** passed every
test in the package. The end-to-end federation has one anchor and one path, so
there was never a choice to make and the rule was never exercised.

`TestTheShortestValidChainIsPreferred` builds a topology with an actual choice: a
leaf naming two superiors, reaching anchor A in three statements and anchor B in
two. Both are trusted, both validate. The longer anchor is listed **first** in
the configuration, so an implementation that takes the first match rather than
the shortest fails.

Recorded because the lesson generalises: a rule about choosing between
alternatives cannot be tested by a fixture that offers one alternative, and a
test suite full of passing tests said nothing about it.

## Automatic Registration (§12.1)

`oidfed.Register` turns a resolved chain into a usable client. An RP in the same
federation uses this OP with **no prior registration step**: its Entity
Identifier is its `client_id`, and everything the OP needs — redirect URIs, keys,
scopes — comes from metadata resolved through a Trust Chain rather than from a
registration request.

This is the feature that makes the rest of the federation work pay off for an
OpenID Provider.

### The chain is not the whole story

A resolved chain establishes **who** an entity is. It does not establish that the
party sending this particular request **is** that entity — anybody can read a
public Entity Configuration and put its identifier in a `client_id`.

§12.1 is explicit about the missing half:

> Since there is no registration step prior to the Authentication Request,
> asymmetric cryptography MUST be used to authenticate requests... the OP neither
> assigns a Client Secret to the RP nor returns it.

> Authentication requests MUST demonstrate that the requesting Entity controls
> the Entity's RP keys... Attempted authentication requests that do not do so
> MUST be rejected.

So `RegisteredClient` carries the RP's published `jwks` out, and there is no path
that produces a client without them. An RP publishing no keys is **refused**
rather than admitted as a client anybody could impersonate by knowing its public
identifier.

### Metadata policy

A superior constrains a subordinate's metadata with `metadata_policy` — which
redirect URIs are permitted, which scopes, which algorithms. §6.1.4:

> If a policy error or another error is encountered during the metadata policy
> resolution or its application, the Trust Chain MUST be considered invalid.

This was previously **refused** — a chain carrying any policy was rejected,
because resolving it and using the leaf's own metadata anyway does not produce a
slightly-wrong client, it produces *the client the RP asked for rather than the
one its federation permits*. That was the right failure while the operators were
unimplemented, and it also meant Signari could not join any federation that uses
policy, which is most of them.

All seven standard operators of §6.1.3.1 are now implemented, along with §6.1.4.1
resolution and §6.1.4.2 application.

#### What the operators actually do

The recurring surprise is that the names suggest checks and several of them are
transformations:

| Operator | Action | Merge of two superiors' values |
|---|---|---|
| `value` | Assigns. `null` **removes** the parameter | Must be **equal**, else a policy error |
| `add` | Union into the parameter; initialises it if absent | Union |
| `default` | Sets only when the parameter is absent | Must be **equal** |
| `one_of` | Checks membership | **Intersection**; empty is an error |
| `subset_of` | **Assigns the intersection** — a modifier, not only a check | Intersection; empty is *fine* |
| `superset_of` | Checks containment | Union |
| `essential` | Requires presence | Logical **OR** |

`subset_of` being a modifier is what lets one policy serve a whole federation:
an RP asking for more than it may have is *trimmed* rather than rejected. And
the merge rules are §6.1.1's Hierarchy principle in arithmetic — intersection
where a value is permitted, union where one is demanded, OR for essential — so a
subordinate can always narrow what a superior allowed and never widen it.

Two more details that are easy to get wrong and silent when you do:

- **`one_of` may not be combined with `add`, `subset_of` or `superset_of`.** It
  constrains a single value; they operate on arrays. The combination is a policy
  error, not a no-op.
- **`scope` is processed as an array** (§6.1.3.1.8) and re-joined with spaces.
  Without this, a `subset_of` on scope compares the whole string
  `"openid profile email"` against individual scope values, matches none, and
  quietly narrows every client in the federation to no scopes at all.

#### Order is load-bearing

Operators run `value` → `add` → `default` → `one_of` → `subset_of` →
`superset_of` → `essential`, which each operator's own definition fixes.

Two positions carry real weight. `superset_of` runs **after** `subset_of`, so a
policy demanding a value its own `subset_of` has just removed fails — that is the
intended outcome for a policy describing a set nothing can satisfy. And
`essential` runs **last**, so it judges the parameter as `default` left it rather
than as the entity published it; moving it earlier refuses entities whose
omission the policy was about to fix.

Both were found by mutation rather than by reading: a mutant moving `essential`
to the front passed every operator test in the file, because nothing else there
distinguishes its position.

#### Ordering against the superior's own metadata

§3.1.1: *"If both `metadata` and `metadata_policy` appear in a Subordinate
Statement, then the stated `metadata` MUST be applied before the
`metadata_policy`."*

So a superior's assigned values are judged by that same superior's policy. The
other order also "works" on any policy the assignment happens to satisfy, which
is why it needs a test that specifically contradicts it.

#### Unknown operators

§6.1.3.2 splits these two ways, and both halves matter:

- An operator we do not understand is **ignored**. Refusing would make every
  federation using any extension operator unusable, whether or not the
  constraint was relevant.
- Unless its name appears in `metadata_policy_crit`, in which case the chain is
  **invalid**. Ignoring it there would admit an entity under a constraint its
  federation believes is in force.

| Mutation | Test that caught it |
|---|---|
| `subset_of` rejects instead of trimming | `TestSubsetOfTrimsRatherThanRejects` |
| `essential` merges with AND | `TestOperatorMergeRules` |
| `one_of` merges to a union | `TestOperatorMergeRules` |
| `subset_of` merges to a union | `TestASubordinateCannotWidenWhatASuperiorForbade` |
| `essential` no longer runs last | `TestEssentialIsJudgedAfterDefaultHasFilledTheParameter` |
| `scope` not treated as an array | `TestScopeIsProcessedAsAnArrayAndRejoined` |
| A critical unknown operator is ignored | `TestACriticalOperatorWeDoNotImplementInvalidatesTheChain` |
| Superior metadata applied after the policy | `TestTheSuperiorsMetadataIsJudgedByItsOwnPolicy` |
| Admit an RP with no published keys | `TestAnRPWithNoKeysIsRefused` |

Also refused: an entity that resolves but publishes no `openid_relying_party`
metadata (being in the federation is not the same as being a relying party), an
RP with no `redirect_uris` (inventing one builds an open redirector), and a
`client_id` that resolves to nothing.

#### One thing deliberately not claimed

§6.1.4.1 calls the merge direction — most superior first — *crucial*, and it is
implemented that way. But with only the standard operators the resolved policy is
the **same read from either end**, because every standard merge is commutative:
union, intersection, equality, OR. A mutation reversing the direction survives
every test here, and that is a property of the operator set rather than a gap in
the tests. The direction still matters for the additional operators §6.1.3.2
permits, whose merges need not be commutative.

## Where it goes next

- **The §8 endpoints** we would serve as an Intermediate or Trust Anchor: fetch,
  subordinate listing, resolve, trust mark status. Signari is a Leaf Entity and
  cannot yet vouch for anybody else.
- **Trust marks** (§7) beyond carrying them: issuing, and the trust mark status
  endpoint.

The resolution side — publish, fetch, build, validate, register — is complete and
tested end to end against multi-entity federations over HTTP.
