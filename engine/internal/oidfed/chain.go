package oidfed

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Trust Chain validation, OpenID Federation 1.0 §10.2.
//
// A Trust Chain is an ordered list of Entity Statements running from the entity
// whose trust is in question up to a Trust Anchor. Validating it is what turns
// "this server published a statement about itself" into "an authority I already
// trust vouches for this server".
//
// # The step that is easy to get backwards
//
// §10.2 verifies ES[0] -- the subject's own Entity Configuration -- TWICE, and
// the two checks do different work:
//
//	"For ES[0] ... verify that its signature validates with a public key in
//	ES[0]["jwks"]."
//
//	"For each j = 0,...,i-1, verify that the signature of ES[j] validates with a
//	public key in ES[j+1]["jwks"]."
//
// The first is a self-signature: it proves the statement is internally
// consistent and proves nothing about trust, because anybody can sign a
// statement with a key they also published in it.
//
// The second is where trust flows. ES[1] is the Subordinate Statement issued by
// the superior ABOUT this entity, and its `jwks` is the key set the superior
// attests the subordinate has. So checking ES[0]'s signature against ES[1]'s
// jwks is asking "does the key this entity signed with match the key its
// superior says it has" -- and an implementation that only does the
// self-signature check has built a chain that validates any entity that can sign
// its own configuration, which is every entity.
//
// Both are implemented. The comment exists because the first one looks like the
// important one.

// Statement is one parsed Entity Statement in a chain.
type Statement struct {
	// Raw is the compact JWS, needed to verify the signature over the exact
	// bytes received rather than over a re-serialisation.
	Raw string

	Issuer   string          `json:"iss"`
	Subject  string          `json:"sub"`
	IssuedAt int64           `json:"iat"`
	Expiry   int64           `json:"exp"`
	JWKS     json.RawMessage `json:"jwks"`

	// Constraints is §6.2, present only on Subordinate Statements. See
	// constraints.go: §10.2 makes enforcing these a MUST, and this engine
	// parsed and ignored them until August 2026.
	Constraints *Constraints `json:"constraints,omitempty"`

	// Crit is §3.2's `crit` claim: the issuer marking extension claims that a
	// reader must understand before it may act on this statement.
	//
	// Distinct from `metadata_policy_crit`, which marks critical POLICY
	// OPERATORS and has been enforced in policy.go since it was written. This
	// one marks critical CLAIMS on the statement itself, and was not read at all
	// -- so an issuer saying "do not use this statement unless you process X"
	// was answered by using it without processing X.
	Crit []string `json:"crit,omitempty"`
}

// ChainResult is a validated chain.
type ChainResult struct {
	// Subject is the entity the chain establishes trust for.
	Subject string
	// TrustAnchor is the Entity Identifier the chain terminates at.
	TrustAnchor string
	// Expiry is the chain's expiry, §10.4: "The expiration time of the whole
	// Trust Chain is the minimum (exp) value within the Trust Chain."
	Expiry time.Time
	// Length is the number of statements.
	Length int
}

// ValidateChain applies §10.2 to an ordered list of Entity Statements.
//
// chain[0] is the subject's Entity Configuration; chain[len-1] is the Trust
// Anchor's. trustAnchorID is the Entity Identifier the caller already trusts --
// supplied by the caller and never read from the chain, because a chain that
// names its own anchor validates against anybody.
//
// trustAnchorKeys is the anchor's key set as the caller holds it, out of band.
// Same reasoning: §10.2's last step is "verify that its signature validates with
// a public key of the Trust Anchor", and taking that key from the chain would
// make the step a tautology.
func ValidateChain(chain []Statement, trustAnchorID string, trustAnchorKeys json.RawMessage,
	now time.Time) (*ChainResult, error) {

	// An upper bound as well as a lower one.
	//
	// Every element costs a signature verification, so the length of a chain is
	// the cost of validating it. Today the only caller is `Resolver.Resolve`,
	// which builds the chain itself under `MaxChainDepth` with cycle detection —
	// so nothing outside this package chooses the length and the bound below is
	// defence in depth rather than a live guard.
	//
	// It is added now because of a door that is currently shut. OID4VCI Appendix
	// F.1 defines a `trust_chain` JOSE header carrying an OpenID Federation trust
	// chain, which this server refuses precisely because it does not evaluate one
	// (see internal/oid4vci/proof.go). Implementing that header means accepting a
	// chain **from the wallet** — a caller-supplied array whose length is
	// attacker-chosen — and routing it here. The bound belongs in the function
	// that validates, not in whichever caller happens to arrive next.
	if len(chain) > MaxChainDepth+1 {
		return nil, fmt.Errorf("the trust chain has %d statements, over the limit of "+
			"%d: each element costs a signature verification, so an unbounded chain "+
			"is unbounded work", len(chain), MaxChainDepth+1)
	}
	if len(chain) < 2 {
		// A chain of one is an Entity Configuration with nothing vouching for
		// it. It may be perfectly valid and it establishes no trust.
		return nil, fmt.Errorf("a Trust Chain needs at least two statements: the "+
			"subject's Entity Configuration and something above it (got %d)", len(chain))
	}
	if trustAnchorID == "" {
		return nil, fmt.Errorf("a trust anchor identifier is required")
	}
	// Deliberately NOT ValidateEntityID here.
	//
	// The anchor identifier arrives from this deployment's own configuration,
	// not from the chain, so its FORM is a configuration question and belongs
	// where the configuration is loaded. What matters at this point is the exact
	// comparison below: does the chain terminate at the string we were told to
	// trust. Re-validating the form here would also put a rule in a pure
	// function that its callers' test escapes cannot reach, so the rule would be
	// exercised in production and bypassed in every test.
	if len(trustAnchorKeys) == 0 {
		return nil, fmt.Errorf("the Trust Anchor's keys must be supplied out of " +
			"band; taking them from the chain would make the final check verify " +
			"the chain against itself")
	}

	// Step 1-3, for every statement.
	minExp := int64(0)
	for j, es := range chain {
		if es.Issuer == "" || es.Subject == "" || es.IssuedAt == 0 || es.Expiry == 0 {
			return nil, fmt.Errorf("statement %d is missing a required claim "+
				"(iss, sub, iat, exp are all REQUIRED by section 3.1.1)", j)
		}
		if len(es.JWKS) == 0 {
			return nil, fmt.Errorf("statement %d carries no jwks", j)
		}
		if err := checkCrit(es); err != nil {
			return nil, fmt.Errorf("statement %d: %w", j, err)
		}
		if !time.Unix(es.IssuedAt, 0).Before(now) {
			return nil, fmt.Errorf("statement %d has an iat in the future", j)
		}
		if !time.Unix(es.Expiry, 0).After(now) {
			return nil, fmt.Errorf("statement %d expired at %s", j,
				time.Unix(es.Expiry, 0).UTC().Format(time.RFC3339))
		}
		// §10.4: the chain expires when its earliest member does.
		if minExp == 0 || es.Expiry < minExp {
			minExp = es.Expiry
		}
	}

	// Step 4: ES[0] is an Entity Configuration, so iss == sub.
	if chain[0].Issuer != chain[0].Subject {
		return nil, fmt.Errorf("the first statement is not an Entity Configuration: "+
			"iss %q != sub %q", chain[0].Issuer, chain[0].Subject)
	}

	// Step 5: ES[0]'s self-signature. Consistency, not trust.
	if err := verifyWith(chain[0], chain[0].JWKS); err != nil {
		return nil, fmt.Errorf("the subject's Entity Configuration is not "+
			"self-signed by a key in its own jwks: %w", err)
	}

	// Step 6 and 7, walking up.
	for j := 0; j < len(chain)-1; j++ {
		if chain[j].Issuer != chain[j+1].Subject {
			return nil, fmt.Errorf("the chain is broken between statement %d and %d: "+
				"iss %q is not the subject of the next statement (%q)",
				j, j+1, chain[j].Issuer, chain[j+1].Subject)
		}
		// THE trust link. See the package comment above.
		if err := verifyWith(chain[j], chain[j+1].JWKS); err != nil {
			return nil, fmt.Errorf("statement %d does not verify against the keys "+
				"its superior attests it has: %w", j, err)
		}
	}

	// Step 8: the last statement must be the anchor we were told to trust.
	last := chain[len(chain)-1]
	if last.Issuer != trustAnchorID {
		return nil, fmt.Errorf("the chain terminates at %q, not at the trust anchor "+
			"%q", last.Issuer, trustAnchorID)
	}

	// Step 9: and it must be signed by the anchor's own key, as held out of band.
	if err := verifyWith(last, trustAnchorKeys); err != nil {
		return nil, fmt.Errorf("the trust anchor's statement does not verify "+
			"against the anchor keys held out of band: %w", err)
	}

	// §10.2's closing MUST: "constraints MUST be enforced for each Subordinate
	// Statement of the Trust Chain, as explained in Section 6.2."
	//
	// Last, after the signatures. A constraint is a statement about what a
	// superior permits, and it is only worth reading once we know the superior
	// actually said it.
	if err := applyConstraints(chain); err != nil {
		return nil, fmt.Errorf("the chain is signed correctly and violates the "+
			"constraints its superiors imposed: %w", err)
	}

	return &ChainResult{
		Subject:     chain[0].Subject,
		TrustAnchor: trustAnchorID,
		Expiry:      time.Unix(minExp, 0),
		Length:      len(chain),
	}, nil
}

// verifyWith checks a statement's signature against a JWK Set.
func verifyWith(es Statement, rawJWKS json.RawMessage) error {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(rawJWKS, &set); err != nil {
		return fmt.Errorf("the key set did not parse: %w", err)
	}
	if len(set.Keys) == 0 {
		return fmt.Errorf("the key set is empty")
	}

	// Asymmetric only, and an allow-list.
	//
	// §3 makes RS256 mandatory-to-implement and permits others. What it does not
	// permit -- and what an allow-list is for -- is a symmetric algorithm, where
	// the "public" key in a published jwks would also be the signing key, so any
	// holder of the statement could re-sign it.
	tok, err := jose.ParseSigned(es.Raw, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.EdDSA,
	})
	if err != nil {
		return fmt.Errorf("the statement did not parse as a signed JWT: %w", err)
	}
	if len(tok.Signatures) != 1 {
		return fmt.Errorf("an Entity Statement must carry exactly one signature")
	}
	// §3: "Entity Statement JWTs MUST include the kid (Key ID) header parameter".
	kid := tok.Signatures[0].Header.KeyID
	if kid == "" {
		return fmt.Errorf("the statement has no kid header, which section 3 requires")
	}

	for _, k := range set.Keys {
		if k.KeyID != kid {
			continue
		}
		if _, err := tok.Verify(k); err != nil {
			return fmt.Errorf("the signature did not verify against key %q: %w", kid, err)
		}
		return nil
	}
	return fmt.Errorf("no key with kid %q in the key set", kid)
}

// knownCritClaims are extension claims this implementation understands well
// enough to act on when an issuer marks them critical.
//
// Empty, and that is the honest state rather than an oversight: §3.2 requires
// each `crit` entry to name a claim "that is not defined by this specification",
// so by construction every possible entry is an extension, and we implement no
// federation extensions.
//
// It exists as a named, empty set so that adding an extension has one obvious
// place to register it -- and so the emptiness is a statement rather than an
// absence.
var knownCritClaims = map[string]bool{}

// checkCrit applies §3.2's rule for the `crit` claim.
//
//	"If the crit Claim is present, then each array element in this Claim's value
//	MUST be a string representing an Entity Statement Claim that is not defined
//	by this specification and that Claim MUST be understood and be able to be
//	processed by the implementation."
//
// followed by:
//
//	"If any of these validation steps fail, the Entity Statement MUST be
//	rejected."
//
// # Why ignoring this is worse than it looks
//
// `crit` is the issuer saying: this statement means something different from
// what it appears to mean, and if you cannot process the named claim you must
// not use it. Reading the statement anyway is not a partial understanding of it
// -- it is acting on a document whose author has told you in advance that you
// will misread it.
//
// That is the same shape as the `constraints` claim in this package, parsed and
// ignored until August 2026, and as `may_act`, the WebAuthn backup-eligibility
// flag and CIBA's signed request object elsewhere in this engine. A sender put a
// restriction in a signed object and the receiver dropped it.
//
// Rejecting every non-empty `crit` is the conformant answer while
// knownCritClaims is empty, and it fails closed: a federation that starts using
// an extension gets a refusal naming the claim, rather than silent
// misinterpretation of statements that govern who may sign in.
func checkCrit(es Statement) error {
	for _, name := range es.Crit {
		if name == "" {
			return fmt.Errorf("the crit claim contains an empty entry")
		}
		if definedClaims[name] {
			// §3.2: an entry must name a claim NOT defined by the specification.
			// Marking `iss` critical is malformed, not a stricter request.
			return fmt.Errorf("the crit claim names %q, which this specification "+
				"defines; crit may only name extension claims", name)
		}
		if !knownCritClaims[name] {
			return fmt.Errorf("the claim %q is declared critical by its issuer and "+
				"this implementation does not process it, so the statement cannot "+
				"be acted on (section 3.2)", name)
		}
	}
	return nil
}

// definedClaims are the Entity Statement claims this specification defines, for
// the "crit may only name extension claims" half of the rule.
var definedClaims = map[string]bool{
	"iss": true, "sub": true, "iat": true, "exp": true, "aud": true, "jti": true,
	"jwks": true, "authority_hints": true, "trust_anchor_hints": true,
	"metadata": true, "metadata_policy": true, "metadata_policy_crit": true,
	"constraints": true, "crit": true, "trust_marks": true,
	"trust_mark_issuers": true, "trust_mark_owners": true,
	"source_endpoint": true,
}
