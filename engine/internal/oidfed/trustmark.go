package oidfed

import (
	"fmt"
	"net/url"
	"time"
)

// Trust Marks, OpenID Federation 1.0 §7, §8.4, §8.5 and §8.6.
//
// A Trust Mark is a signed statement by an accreditation authority that some
// entity conforms to a set of criteria. It is the federation's answer to "this
// server is technically reachable and cryptographically genuine, but is it
// ALLOWED to do what it is asking to do" -- a question a Trust Chain does not
// answer, because a chain proves provenance and says nothing about conformance.
//
// # What is here
//
//   - Issuing: Build, BuildDelegation.
//   - Validating: ValidateTrustMark (§7.3), ValidateDelegation (§7.2.2), and
//     ValidateTrustMarksClaim, which is the SYNTACTIC check §3.1.2 requires and
//     which is deliberately separate from the trust evaluation.
//   - The Trust Anchor's two governing claims, trust_mark_issuers and
//     trust_mark_owners, with their lookup rules.
//
// # The claim name that changed
//
// The identifier claim is `trust_mark_type`. Earlier drafts of this
// specification called it `id`, and a great deal of deployed code and a great
// deal of written-down knowledge still says `id`. A Trust Mark carrying `id`
// is not a Trust Mark this specification defines, and one carrying both is a
// document that means two things. Only `trust_mark_type` is read and only
// `trust_mark_type` is written; see the rejection in parseTrustMark.
//
// # Why validation takes the issuer's keys as an argument
//
// §7.3: "The trust in the Trust Mark Issuer comes before the trust in the trust
// mark... An Entity MUST therefore establish trust in the Trust Mark Issuer by
// following the procedure defined in Section 10 prior to starting the Trust
// Mark validation process defined below."
//
// So the keys arrive from a completed chain resolution, held by the caller,
// never read out of the Trust Mark itself. This is the same shape as
// ValidateChain taking the anchor's keys out of band, and for the same reason:
// a document that supplies the key that verifies it verifies nothing.

const (
	// TrustMarkTyp is §7's required explicit type.
	//
	// "The typ header parameter value MUST be trust-mark+jwt unless the trust
	// framework in use defines a more specific media type value for the
	// particular kind of Trust Mark."
	//
	// The escape hatch in that sentence is not taken. A framework-specific typ
	// is only meaningful to a reader that knows the framework, and accepting an
	// arbitrary one here would mean accepting any typ at all -- which is the
	// cross-JWT confusion the requirement exists to prevent.
	TrustMarkTyp = "trust-mark+jwt"

	// DelegationTyp is §7.2.1's.
	DelegationTyp = "trust-mark-delegation+jwt"

	// StatusResponseTyp is §8.4.2's.
	StatusResponseTyp = "trust-mark-status-response+jwt"

	// TrustMarkMediaType is what §8.6.2 serves.
	TrustMarkMediaType = "application/trust-mark+jwt"

	// StatusResponseMediaType is what §8.4.2 serves.
	StatusResponseMediaType = "application/trust-mark-status-response+jwt"
)

// Trust Mark status values, §8.4.2.
//
// "Additional status values MAY be defined and used in addition to those
// above." None are defined here: a status a reader does not recognise is one it
// cannot act on, and inventing one would put this deployment's private
// vocabulary into a federation's decision path.
const (
	StatusActive  = "active"
	StatusExpired = "expired"
	StatusRevoked = "revoked"
	StatusInvalid = "invalid"
)

// TrustMark is the claim set of a Trust Mark JWT, §7.1.
type TrustMark struct {
	// Issuer is the Entity Identifier of the Trust Mark Issuer. REQUIRED.
	Issuer string `json:"iss"`
	// Subject is the entity the mark applies to. REQUIRED.
	Subject string `json:"sub"`
	// Type is the Trust Mark type identifier. REQUIRED.
	//
	// §7.1: "MUST be collision-resistant across multiple federations. It is
	// RECOMMENDED that the identifier value is built using a URL that uniquely
	// identifies the federation or the trust framework within which it was
	// issued."
	Type string `json:"trust_mark_type"`
	// IssuedAt is REQUIRED.
	IssuedAt int64 `json:"iat"`

	// Expiry is OPTIONAL. §7.1: "If not present, it means that the Trust Mark
	// does not expire."
	//
	// omitempty is correct and load-bearing: zero must serialise as ABSENT, not
	// as `"exp": 0`, which would be a mark that expired in 1970.
	Expiry int64 `json:"exp,omitempty"`

	LogoURI string `json:"logo_uri,omitempty"`
	Ref     string `json:"ref,omitempty"`

	// Delegation is §7.2's delegation claim: a Trust Mark Delegation JWT, as a
	// compact serialisation.
	Delegation string `json:"delegation,omitempty"`
}

// Delegation is the claim set of a Trust Mark Delegation JWT, §7.2.1.
type Delegation struct {
	// Issuer is the Trust Mark OWNER. Subject is the delegated ISSUER.
	//
	// The direction is the whole point and is easy to write backwards: the owner
	// is making a statement about who may issue on its behalf, so the owner is
	// `iss` and the delegate is `sub`.
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Type     string `json:"trust_mark_type"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp,omitempty"`
	Ref      string `json:"ref,omitempty"`
}

// TrustMarkEntry is one element of the `trust_marks` claim, §3.1.2.
//
// Two representations of the same identifier, and the specification requires
// them to agree -- see ValidateTrustMarksClaim.
type TrustMarkEntry struct {
	Type string `json:"trust_mark_type"`
	JWT  string `json:"trust_mark"`
}

// StatusResponse is the claim set of a Trust Mark Status Response JWT, §8.4.2.
//
// Note what this is NOT: a JSON body saying `{"active": true}`. Earlier drafts
// of this specification answered the status endpoint that way and a good deal of
// deployed code still expects it. The Final specification's response is a SIGNED
// JWT, which is the difference between a status a network attacker can flip and
// one they cannot.
type StatusResponse struct {
	Issuer    string `json:"iss"`
	IssuedAt  int64  `json:"iat"`
	TrustMark string `json:"trust_mark"`
	Status    string `json:"status"`
}

// TrustMarkParams is what a Trust Mark is minted from.
type TrustMarkParams struct {
	Issuer  string
	Subject string
	Type    string
	// Lifetime bounds the mark. Zero means no `exp`, which §7.1 permits and
	// which §7.3 then recommends compensating for with the status endpoint --
	// see the note in Build.
	Lifetime time.Duration
	LogoURI  string
	Ref      string
	// Delegation is a compact Trust Mark Delegation JWT, when this issuer is not
	// the owner of the type identifier.
	Delegation string
}

// BuildTrustMark assembles and validates a Trust Mark claim set.
//
// Validation lives here rather than at the caller because each rule below is a
// MUST with a plausible wrong answer that looks fine in a response body.
func BuildTrustMark(p TrustMarkParams, now time.Time) (*TrustMark, error) {
	if err := ValidateEntityID(p.Issuer); err != nil {
		return nil, fmt.Errorf("the Trust Mark issuer: %w", err)
	}
	if err := ValidateEntityID(p.Subject); err != nil {
		return nil, fmt.Errorf("the Trust Mark subject: %w", err)
	}
	if err := ValidateTrustMarkType(p.Type); err != nil {
		return nil, err
	}
	if p.Lifetime < 0 {
		return nil, fmt.Errorf("a Trust Mark lifetime cannot be negative")
	}
	if p.LogoURI != "" {
		if err := requireHTTPS(p.LogoURI, "logo_uri"); err != nil {
			return nil, err
		}
	}
	if p.Ref != "" {
		if err := requireHTTPS(p.Ref, "ref"); err != nil {
			return nil, err
		}
	}

	tm := &TrustMark{
		Issuer:     p.Issuer,
		Subject:    p.Subject,
		Type:       p.Type,
		IssuedAt:   now.Unix(),
		LogoURI:    p.LogoURI,
		Ref:        p.Ref,
		Delegation: p.Delegation,
	}
	// A Trust Mark with no lifetime is permitted and is a commitment: §7.3's
	// expiry step becomes vacuous, so the only way a reader can learn the mark
	// has been withdrawn is to ask the status endpoint. The caller decides;
	// the CLI that reaches this warns, and the status endpoint exists.
	if p.Lifetime > 0 {
		tm.Expiry = now.Add(p.Lifetime).Unix()
	}
	return tm, nil
}

// DelegationParams is what a delegation is minted from.
type DelegationParams struct {
	// Owner is the Trust Mark Owner -- the `iss` of the delegation.
	Owner string
	// Delegate is the Trust Mark Issuer being authorised -- the `sub`.
	Delegate string
	Type     string
	Lifetime time.Duration
	Ref      string
}

// BuildDelegation assembles a Trust Mark Delegation claim set, §7.2.1.
func BuildDelegation(p DelegationParams, now time.Time) (*Delegation, error) {
	if err := ValidateEntityID(p.Owner); err != nil {
		return nil, fmt.Errorf("the Trust Mark owner: %w", err)
	}
	if err := ValidateEntityID(p.Delegate); err != nil {
		return nil, fmt.Errorf("the delegated issuer: %w", err)
	}
	if err := ValidateTrustMarkType(p.Type); err != nil {
		return nil, err
	}
	if p.Owner == p.Delegate {
		// A delegation to oneself is not an error the specification names, and it
		// is refused anyway: §7.2 exists because "the owner of a Trust Mark ...
		// does not match the Trust Mark Issuer". A self-delegation is a document
		// that answers a question nobody asked, and §7.3 only requires a
		// delegation when the owner is somebody else -- so one that says
		// otherwise is more likely a mistake in a script than an intention.
		return nil, fmt.Errorf("a delegation from %q to itself says nothing: "+
			"section 7.2 exists for the case where the issuer is not the owner",
			p.Owner)
	}
	if p.Lifetime < 0 {
		return nil, fmt.Errorf("a delegation lifetime cannot be negative")
	}
	if p.Ref != "" {
		if err := requireHTTPS(p.Ref, "ref"); err != nil {
			return nil, err
		}
	}
	d := &Delegation{
		Issuer:   p.Owner,
		Subject:  p.Delegate,
		Type:     p.Type,
		IssuedAt: now.Unix(),
		Ref:      p.Ref,
	}
	if p.Lifetime > 0 {
		d.Expiry = now.Add(p.Lifetime).Unix()
	}
	return d, nil
}

// ValidateTrustMarkType applies §7.1's constraint on a type identifier.
//
// The specification says the identifier "MUST be collision-resistant across
// multiple federations" and RECOMMENDS a URL. A bare word like "certified" is
// exactly the collision it warns about -- two federations both mint it and a
// reader that trusts one now trusts the other's.
//
// So: a URL is required, not merely recommended. That is stricter than the text,
// and the strictness is confined to what THIS server issues and accepts; a
// federation whose framework mints opaque identifiers would need this relaxed,
// and would be relaxing a rule it can see rather than discovering a silent one.
func ValidateTrustMarkType(id string) error {
	if id == "" {
		return fmt.Errorf("a Trust Mark type identifier is required (section 7.1)")
	}
	u, err := url.Parse(id)
	if err != nil {
		return fmt.Errorf("the Trust Mark type identifier %q does not parse as a "+
			"URL: %w", id, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("the Trust Mark type identifier %q is not an absolute "+
			"URL; section 7.1 requires an identifier that is collision-resistant "+
			"across federations, and a bare name is the collision it warns about", id)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("the Trust Mark type identifier %q uses the %q scheme; "+
			"an http(s) URL is what section 7.1 recommends", id, u.Scheme)
	}
	return nil
}

func requireHTTPS(raw, field string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s %q does not parse as a URL: %w", field, raw, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%s %q must use the https scheme", field, raw)
	}
	if u.Host == "" {
		return fmt.Errorf("%s %q has no host", field, raw)
	}
	return nil
}
