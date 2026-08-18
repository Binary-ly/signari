// Package oidfed implements OpenID Federation 1.0 (Final, 17 February 2026).
//
// # What is here and what is not
//
// The Entity Configuration only: the self-signed Entity Statement an entity
// publishes about itself at its configuration endpoint. That is the foundation
// everything else in the specification stands on — a Trust Chain is a sequence
// of Entity Statements, and the leaf of every chain is a configuration like this
// one.
//
// The federation endpoints (§8: fetch, subordinate listing, resolve, trust mark
// status) are NOT implemented, and nothing here advertises them. That is
// deliberate: this repository's rule is that an endpoint enters a metadata
// document only once it works, and a `federation_fetch_endpoint` pointing at a
// 404 is worse than its absence — a federation operator would configure us as an
// Intermediate and discover the gap when a chain fails to resolve.
//
// # Why the signing key is separate
//
// §3.1.1, of the `jwks` claim:
//
//	"These Federation Entity Keys SHOULD NOT be used in other protocols. (Keys to
//	be used in other protocols, such as OpenID Connect, are conveyed in the
//	metadata elements for the protocol's Entity Type Identifiers...)"
//
// The naive implementation reuses the OIDC signing key: it is already there and
// already published. But the two keys answer different questions. A relying
// party trusts our OIDC key to assert who a user is; a federation trusts our
// federation key to assert what this entity is and who vouches for it. Rotating
// one should not rotate the other, and a compromise of one should not forge the
// other.
package oidfed

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Typ is the explicit type header, §3: "typed, by setting the typ header
// parameter to entity-statement+jwt to prevent cross-JWT confusion".
const Typ = "entity-statement+jwt"

// MediaType is what the configuration endpoint serves.
const MediaType = "application/entity-statement+jwt"

// WellKnownPath is appended to the Entity Identifier, §9.
const WellKnownPath = "/.well-known/openid-federation"

// EntityConfiguration is a self-signed Entity Statement.
//
// The claim set is §3.1.1 and §3.1.2. Only what we can honestly assert is
// included; every optional claim we do not populate is absent rather than empty,
// because in this specification an empty array is frequently forbidden outright
// rather than merely meaningless.
type EntityConfiguration struct {
	// Issuer and Subject are both the Entity Identifier. §3.1.1: "If the iss and
	// the sub are identical, the issuer is making an Entity Statement about
	// itself called an Entity Configuration."
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`

	IssuedAt int64 `json:"iat"`
	Expiry   int64 `json:"exp"`

	// JWKS is the Federation Entity signing keys, REQUIRED.
	JWKS json.RawMessage `json:"jwks"`

	// AuthorityHints names our Immediate Superiors.
	//
	// §3.1.2: "REQUIRED in Entity Configurations of the Entities that have at
	// least one Superior above them... MUST NOT be the empty array []. This
	// Claim MUST NOT be present in Entity Configurations of Trust Anchors with
	// no Superiors."
	//
	// Three states, not two: present and non-empty, or absent. `omitempty`
	// collapses nil and `[]` to absent, which is exactly right here — the one
	// value that must never appear on the wire is the empty array.
	AuthorityHints []string `json:"authority_hints,omitempty"`

	// TrustAnchorHints, same rule (§3.1.2).
	TrustAnchorHints []string `json:"trust_anchor_hints,omitempty"`

	// Metadata declares the Entity Types this entity plays (§5.1).
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Params is what a configuration is built from.
type Params struct {
	// EntityID is the Entity Identifier. §9 requires https, a host component,
	// and permits port and path.
	EntityID string
	// FederationJWKS is the marshalled JWK Set of federation keys.
	FederationJWKS json.RawMessage
	// AuthorityHints and TrustAnchorHints are nil for a Trust Anchor with no
	// superiors, and otherwise non-empty.
	AuthorityHints   []string
	TrustAnchorHints []string
	// Lifetime bounds the statement.
	Lifetime time.Duration
	// Metadata is the per-Entity-Type metadata.
	Metadata map[string]any
}

// Build assembles and validates an Entity Configuration.
//
// Validation happens here rather than at the caller because every rule below is
// one the specification states as a MUST and each has a plausible wrong answer
// that looks fine in a response body. An empty `authority_hints` array in
// particular is what a naive implementation emits for "no superiors", and it is
// the one value §3.1.2 forbids.
func Build(p Params, now time.Time) (*EntityConfiguration, error) {
	if err := ValidateEntityID(p.EntityID); err != nil {
		return nil, err
	}
	if len(p.FederationJWKS) == 0 {
		return nil, fmt.Errorf("the federation JWK Set is required (section 3.1.1); " +
			"an Entity Configuration with no keys cannot be verified by anybody")
	}
	// The empty array is forbidden for both hint claims. Refused rather than
	// silently normalised to absent: a caller passing `[]string{}` believes it
	// is saying something, and what it believes it is saying is wrong.
	if p.AuthorityHints != nil && len(p.AuthorityHints) == 0 {
		return nil, fmt.Errorf("authority_hints must not be the empty array " +
			"(section 3.1.2); pass nil for a Trust Anchor with no superiors")
	}
	if p.TrustAnchorHints != nil && len(p.TrustAnchorHints) == 0 {
		return nil, fmt.Errorf("trust_anchor_hints must not be the empty array " +
			"(section 3.1.2); pass nil if there are none")
	}
	for _, h := range p.AuthorityHints {
		if err := ValidateEntityID(h); err != nil {
			return nil, fmt.Errorf("authority hint %q: %w", h, err)
		}
	}
	for _, h := range p.TrustAnchorHints {
		if err := ValidateEntityID(h); err != nil {
			return nil, fmt.Errorf("trust anchor hint %q: %w", h, err)
		}
	}
	if p.Lifetime <= 0 {
		return nil, fmt.Errorf("an Entity Configuration needs a positive lifetime")
	}

	return &EntityConfiguration{
		Issuer:           p.EntityID,
		Subject:          p.EntityID,
		IssuedAt:         now.Unix(),
		Expiry:           now.Add(p.Lifetime).Unix(),
		JWKS:             p.FederationJWKS,
		AuthorityHints:   p.AuthorityHints,
		TrustAnchorHints: p.TrustAnchorHints,
		Metadata:         p.Metadata,
	}, nil
}

// ValidateEntityID applies §9's constraints on an Entity Identifier.
//
//	"the Entity Identifier (which MUST use the https scheme and contain a host
//	component and MAY also contain port and path components)"
func ValidateEntityID(id string) error {
	if id == "" {
		return fmt.Errorf("an Entity Identifier is required")
	}
	u, err := url.Parse(id)
	if err != nil {
		return fmt.Errorf("%q does not parse as a URL: %w", id, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("the Entity Identifier %q must use the https scheme "+
			"(section 9)", id)
	}
	if u.Host == "" {
		return fmt.Errorf("the Entity Identifier %q has no host component "+
			"(section 9)", id)
	}
	// Query and fragment are not among the permitted components: §9 allows a
	// host, a port and a path, and the configuration endpoint is built by string
	// concatenation, so anything after the path would land in the wrong place.
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("the Entity Identifier %q must not carry a query or "+
			"fragment: the configuration endpoint is formed by appending %q to "+
			"it, which those would break", id, WellKnownPath)
	}
	if u.User != nil {
		return fmt.Errorf("the Entity Identifier %q must not contain user "+
			"information", id)
	}
	return nil
}

// ConfigurationURL is where an entity's configuration is published.
//
// §9: "Its location is determined by concatenating the string
// /.well-known/openid-federation to the Entity Identifier... If the Entity
// Identifier contains a trailing "/" character, it MUST be removed before
// concatenating".
//
// The trailing-slash rule is the whole reason this is a function. Concatenating
// naively produces `https://entity.example//.well-known/openid-federation`,
// which many servers answer and some do not, so it fails intermittently across a
// federation rather than consistently.
func ConfigurationURL(entityID string) (string, error) {
	if err := ValidateEntityID(entityID); err != nil {
		return "", err
	}
	return strings.TrimRight(entityID, "/") + WellKnownPath, nil
}
