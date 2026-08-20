package oidfed

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Chain building: assembling a Trust Chain from an entity up to a Trust Anchor.
//
// This is the loop that joins the two halves. `Fetcher` retrieves statements and
// verifies nothing; `ValidateChain` verifies a complete chain and fetches
// nothing. Neither is useful alone, and keeping them apart is what makes the
// validator testable without a network and the fetcher testable without keys.
//
// # Why building and validating are separate passes
//
// It is tempting to verify each statement as it arrives and stop early on the
// first bad one. That cannot work: §10.2 verifies ES[j] against ES[j+1]'s key
// set, so no statement can be checked until the one ABOVE it has been fetched.
// A resolver that validates incrementally is either doing it wrong or doing it
// against the statement's own keys, which is the self-signature that proves
// nothing.
//
// So: fetch the whole candidate chain, then hand it to the validator. The cost
// is fetching statements that a later failure discards, which is the correct
// trade when the alternative is a validator that accepts anybody.

// TrustAnchor is an anchor the resolver already trusts.
//
// Keys are held here, out of band, because §10.2's final step verifies the
// anchor's statement against "a public key of the Trust Anchor" — and a key read
// from the chain would make that step verify the chain against itself.
type TrustAnchor struct {
	EntityID string
	JWKS     json.RawMessage
}

// Resolver builds and validates Trust Chains.
type Resolver struct {
	Fetcher *Fetcher
	// Anchors are the Trust Anchors this deployment accepts. A chain must
	// terminate at one of them.
	Anchors []TrustAnchor
	// MaxDepth bounds the walk. Zero uses MaxChainDepth.
	MaxDepth int
}

func (r *Resolver) maxDepth() int {
	if r.MaxDepth > 0 {
		return r.MaxDepth
	}
	return MaxChainDepth
}

// Resolve establishes trust in an entity, returning the validated chain.
//
// Every anchor is tried, and the SHORTEST valid chain wins. §10.3: "If multiple
// valid Trust Chains are found, Party A will need to decide on which one to use.
// One simple rule would be to prefer a shorter chain over a longer one."
//
// Shorter is preferred because each additional Intermediate is another party who
// can vouch for something, so the shortest chain is the one with the fewest
// entities able to change the answer.
func (r *Resolver) Resolve(ctx context.Context, entityID string, now time.Time) (*ChainResult, error) {
	res, _, err := r.resolveWithChain(ctx, entityID, now)
	return res, err
}

// resolveWithChain is Resolve, also returning the statements.
//
// Metadata resolution needs the whole chain, not just the verdict -- a
// Subordinate Statement's metadata_policy is a property of the chain that the
// ChainResult deliberately does not carry, because a result summarising "valid"
// should not also be the thing callers read policy from.
func (r *Resolver) resolveWithChain(ctx context.Context, entityID string,
	now time.Time) (*ChainResult, []Statement, error) {
	if len(r.Anchors) == 0 {
		return nil, nil, fmt.Errorf("no trust anchors are configured, so no chain " +
			"can terminate anywhere trusted")
	}
	// Entity identifiers are validated by the Fetcher, which is where the
	// transport policy lives. Re-checking here would be a second copy of the
	// rule that the Fetcher's own test escape cannot reach -- so it would be
	// correct in production and wrong in every test, which is how a rule ends up
	// only being exercised in one of the two.
	leaf, err := r.Fetcher.EntityConfigurationOf(ctx, entityID)
	if err != nil {
		return nil, nil, err
	}

	var best *ChainResult
	var bestChain []Statement
	var firstErr error
	for _, anchor := range r.Anchors {
		chain, berr := r.buildTo(ctx, leaf, anchor.EntityID, now)
		if berr != nil {
			if firstErr == nil {
				firstErr = berr
			}
			continue
		}
		res, verr := ValidateChain(chain, anchor.EntityID, anchor.JWKS, now)
		if verr != nil {
			if firstErr == nil {
				firstErr = verr
			}
			continue
		}
		if best == nil || res.Length < best.Length {
			best, bestChain = res, chain
		}
	}
	if best == nil {
		if firstErr != nil {
			return nil, nil, fmt.Errorf("no valid trust chain from %s to any "+
				"configured anchor: %w", entityID, firstErr)
		}
		return nil, nil, fmt.Errorf("no valid trust chain from %s to any configured "+
			"anchor", entityID)
	}
	return best, bestChain, nil
}

// buildTo walks upward from a leaf towards one named anchor.
//
// Returns the ordered statement list §10.2 expects: the subject's Entity
// Configuration first, each superior's Subordinate Statement after it.
func (r *Resolver) buildTo(ctx context.Context, leaf Statement, anchorID string,
	now time.Time) ([]Statement, error) {

	chain := []Statement{leaf}
	current := leaf
	// Cycle detection by entity, not by depth alone. A federation that names
	// itself as its own superior would otherwise consume the whole depth budget
	// before failing, and the error would blame the depth rather than the cycle.
	seen := map[string]bool{strings.TrimRight(leaf.Subject, "/"): true}

	for depth := 0; depth < r.maxDepth(); depth++ {
		hints, err := AuthorityHintsOf(current, r.Fetcher.AllowLoopbackForTesting)
		if err != nil {
			return nil, err
		}
		if len(hints) == 0 {
			// No superiors. This is only a valid chain if we are already at the
			// anchor -- which the caller checks -- and otherwise means the walk
			// ran out of federation before it ran out of trust.
			return nil, fmt.Errorf("%s has no authority_hints, so there is no path "+
				"upward to %s", current.Subject, anchorID)
		}

		// Prefer the hint that IS the anchor we are aiming at. A leaf with
		// several superiors otherwise sends us up an arbitrary branch, and the
		// first one tried is decided by whoever wrote the document.
		next := ""
		for _, h := range hints {
			if strings.TrimRight(h, "/") == strings.TrimRight(anchorID, "/") {
				next = h
				break
			}
		}
		if next == "" {
			next = hints[0]
		}
		if seen[strings.TrimRight(next, "/")] {
			return nil, fmt.Errorf("the federation graph contains a cycle at %s", next)
		}
		seen[strings.TrimRight(next, "/")] = true

		// The superior's own configuration tells us where to fetch from.
		superior, err := r.Fetcher.EntityConfigurationOf(ctx, next)
		if err != nil {
			return nil, err
		}
		endpoint, err := FetchEndpointOf(superior)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", next, err)
		}

		// The superior's statement ABOUT the entity below it. This is the one
		// carrying the attested key set that §10.2 step 7 checks against.
		sub, err := r.Fetcher.SubordinateStatement(ctx, endpoint, current.Subject)
		if err != nil {
			return nil, err
		}
		chain = append(chain, sub)

		if strings.TrimRight(next, "/") == strings.TrimRight(anchorID, "/") {
			return chain, nil
		}
		current = superior
	}
	return nil, fmt.Errorf("no path from the entity to %s within %d hops",
		anchorID, r.maxDepth())
}

// FetchEndpointOf reads `federation_fetch_endpoint` from an entity's
// `federation_entity` metadata (§5.1.1).
func FetchEndpointOf(st Statement) (string, error) {
	parts := strings.Split(st.Raw, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("not a compact JWS")
	}
	payload, err := b64Payload(parts[1])
	if err != nil {
		return "", err
	}
	var claims struct {
		Metadata struct {
			FederationEntity struct {
				FetchEndpoint string `json:"federation_fetch_endpoint"`
			} `json:"federation_entity"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	ep := claims.Metadata.FederationEntity.FetchEndpoint
	if ep == "" {
		return "", fmt.Errorf("publishes no federation_fetch_endpoint, so no " +
			"statement about a subordinate can be retrieved from it")
	}
	return ep, nil
}

// Entity Type Identifiers, §5.1.
const (
	TypeFederationEntity = "federation_entity"
	TypeRelyingParty     = "openid_relying_party"
	TypeProvider         = "openid_provider"
)

// MetadataOf resolves one Entity Type's metadata for the chain subject.
//
// This is §6.1.4.2 Application, and the order below is the specification's:
//
//  1. Start from the subject's own Entity Configuration metadata.
//  2. Apply the Immediate Superior's `metadata` claim, if any. §3.1.1: "Metadata
//     parameters in a Subordinate Statement have precedence and override
//     identically named parameters under the same Entity Type in the subject's
//     Entity Configuration."
//  3. Apply the resolved metadata policy. §3.1.1 again, on the ordering: "If both
//     metadata and metadata_policy appear in a Subordinate Statement, then the
//     stated metadata MUST be applied before the metadata_policy."
//
// Step 2 before step 3 is not a detail. A superior that supplies a value and
// also constrains it expects its own value to be the one the constraint judges;
// applying the policy to the subject's published value and only then overriding
// it would let the override escape the very policy that superior wrote.
func MetadataOf(chain []Statement, entityType string) (map[string]any, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("an empty chain has no subject")
	}

	md, err := declaredMetadataOf(chain[0], entityType)
	if err != nil {
		return nil, err
	}
	if md == nil {
		return nil, fmt.Errorf("%s declares no %s metadata, so it does not play "+
			"that role in this federation", chain[0].Subject, entityType)
	}

	// The Immediate Superior is chain[1]: the statement about the subject.
	//
	// §3.1.1 limits what it can do: "When metadata is used in a Subordinate
	// Statement, it applies only to those Entity Types that are present in the
	// subject's Entity Configuration." A superior cannot give a subject a role it
	// did not claim -- which is why this runs only after the block above has
	// established the subject declares this type.
	if len(chain) > 1 {
		sup, serr := superiorMetadataOf(chain[1])
		if serr != nil {
			return nil, serr
		}
		for k, v := range sup[entityType] {
			md[k] = v
		}
	}

	// §6.2.3, and the ordering is the specification's: "This MUST be done before
	// applying Metadata Policies but after applying Metadata from a direct
	// superior's Subordinate Statement." So it sits exactly here, between the
	// two blocks above and below it.
	//
	// The spec frames this as removing disallowed Entity Types from the metadata
	// claim. This function resolves one type at a time, so removal becomes
	// refusal: a caller asking for a type the chain's constraints exclude gets
	// the same answer it would get if the type had been stripped.
	if err := entityTypeAllowed(chain, entityType); err != nil {
		return nil, err
	}

	policy, perr := ResolvePolicy(chain)
	if perr != nil {
		return nil, perr
	}
	if policy == nil {
		// §6.1.4.2: "If the process... found no Subordinate Statements in the
		// Trust Chain with a metadata_policy Claim, the metadata of the Trust
		// Chain subject resolves simply to the metadata found in its Entity
		// Configuration, with any metadata parameters provided by the Immediate
		// Superior applied to it."
		return md, nil
	}
	return ApplyPolicy(entityType, md, policy[entityType])
}

// declaredMetadataOf reads one Entity Type's metadata from a statement.
//
// Returns nil, nil when the type is absent, which is different from an empty
// object: §3.1.1 says an entity declares each role it plays "even if the values
// are the empty JSON object {}", so `{}` means "plays this role, publishes
// nothing" and absence means "does not play this role".
func declaredMetadataOf(st Statement, entityType string) (map[string]any, error) {
	payload, err := claimsOf(st)
	if err != nil {
		return nil, err
	}
	var claims struct {
		Metadata map[string]json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	raw, ok := claims.Metadata[entityType]
	if !ok {
		return nil, nil
	}
	md := map[string]any{}
	if err := json.Unmarshal(raw, &md); err != nil {
		return nil, fmt.Errorf("the %s metadata did not parse: %w", entityType, err)
	}
	return md, nil
}

func claimsOf(st Statement) ([]byte, error) {
	parts := strings.Split(st.Raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a compact JWS")
	}
	return b64Payload(parts[1])
}
