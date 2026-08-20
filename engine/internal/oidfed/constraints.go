package oidfed

import (
	"fmt"
	"net/url"
	"strings"
)

// Constraints is §6.2's `constraints` claim on a Subordinate Statement.
//
// "Trust Anchors and Intermediate Entities MAY define constraining criteria that
// apply to their Subordinates."
//
// §10.2 closes trust chain validation with a MUST that was not implemented here:
//
//	"Furthermore, constraints MUST be enforced for each Subordinate Statement of
//	the Trust Chain, as explained in Section 6.2."
//
// and §6.2 says what enforcement means:
//
//	"When resolving the Trust Chain for an Entity the constraints Claim in each
//	Subordinate Statement MUST be independently applied, if present. If any of
//	the constraints checks fails, the Trust Chain MUST be considered invalid."
//
// # Why this is the security control it looks like
//
// Without naming constraints a Trust Anchor that delegates to an Intermediate
// cannot bound what that Intermediate may vouch for. The Intermediate can issue a
// Subordinate Statement about ANY entity identifier -- including one belonging to
// a different organisation in the same federation -- and the chain validates,
// because every signature is genuine and every link joins up.
//
// That is precisely the problem RFC 5280 name constraints exist to solve in
// X.509, and §6.2.2 borrows their syntax outright. A federation without them
// trusts every Intermediate as much as it trusts its Trust Anchor.
//
// This engine had MaxChainDepth, a local ceiling that stops a cycle of entities
// naming each other as superiors from being walked forever. That is a denial of
// service guard and it is not this: it bounds what WE will do, not what a
// superior has said its subtree may contain.
type Constraints struct {
	// MaxPathLength is §6.2.1. A pointer because zero is meaningful -- "no
	// Intermediates MAY appear between this Entity and the Trust Chain subject"
	// -- and is the strictest value, not the absent one.
	MaxPathLength *int `json:"max_path_length,omitempty"`

	NamingConstraints *NamingConstraints `json:"naming_constraints,omitempty"`

	// AllowedEntityTypes is §6.2.3. A pointer for the same reason: the empty
	// array is not absence. "If the constraint is the empty array [], it means
	// that only the federation_entity Entity Type is allowed."
	AllowedEntityTypes *[]string `json:"allowed_entity_types,omitempty"`
}

// NamingConstraints is §6.2.2, using RFC 5280 §4.2.1.10 domain syntax.
type NamingConstraints struct {
	Permitted []string `json:"permitted,omitempty"`
	Excluded  []string `json:"excluded,omitempty"`
}

// FederationEntityType is always allowed and MUST NOT appear in the constraint
// (§6.2.3).
const FederationEntityType = "federation_entity"

// applyConstraints enforces §6.2 across a validated chain.
//
// chain[0] is the subject's Entity Configuration; chain[j] for j >= 1 is a
// Subordinate Statement whose issuer is the constraining entity.
//
// Each statement's constraints are applied INDEPENDENTLY, as §6.2 requires --
// not merged into a running minimum. Merging would be a reasonable-looking
// optimisation that changes the answer: a chain can satisfy every constraint
// separately while no single combined value describes it, which is exactly the
// case §6.2.1's third worked example describes ("Neither TA nor I2 specifies any
// max_path_length constraint while I1 sets max_path_length to 0").
func applyConstraints(chain []Statement) error {
	for j := 1; j < len(chain); j++ {
		c := chain[j].Constraints
		if c == nil {
			continue
		}

		// §6.2.1. The number of Intermediates between the issuer of chain[j] and
		// the subject of the chain is j-1.
		//
		// Worked from the specification's own example: for LE, I1-about-LE,
		// I2-about-I1, TA-about-I2, the constraint on TA's statement (j=3) sees
		// two Intermediates (I1 and I2), which is j-1. §6.2.1 says that chain
		// "does not fulfill the constraints if... The TA sets the
		// max_path_length to 1", and 1 < 2 refuses it here.
		if c.MaxPathLength != nil {
			if *c.MaxPathLength < 0 {
				return fmt.Errorf("statement %d sets a negative max_path_length (%d); "+
					"§6.2.1 requires a value greater than or equal to zero",
					j, *c.MaxPathLength)
			}
			if intermediates := j - 1; intermediates > *c.MaxPathLength {
				return fmt.Errorf("statement %d (issued by %q) sets max_path_length "+
					"%d and this chain puts %d Intermediate(s) between it and %q",
					j, chain[j].Issuer, *c.MaxPathLength, intermediates, chain[0].Subject)
			}
		}

		// §6.2.2. The constraint governs "the Entity Identifiers of Subordinate
		// Entities in a Trust Chain" -- everything below the entity that set it,
		// which is chain[0..j-1].
		if nc := c.NamingConstraints; nc != nil {
			for k := 0; k < j; k++ {
				name := chain[k].Subject
				if err := nc.permits(name); err != nil {
					return fmt.Errorf("statement %d (issued by %q) constrains the "+
						"names below it, and %q fails: %w", j, chain[j].Issuer, name, err)
				}
			}
		}
	}
	return nil
}

// permits applies §6.2.2 to one Entity Identifier.
func (nc *NamingConstraints) permits(entityID string) error {
	host, err := hostOf(entityID)
	if err != nil {
		return err
	}

	// "Any name matching a restriction in the excluded list is invalid,
	// regardless of the information appearing in the permitted list."
	//
	// Excluded is checked FIRST and wins outright. A permitted entry that also
	// matches does not rescue it -- which is the whole point of having both, and
	// the ordering an implementation gets wrong by checking permitted first and
	// returning early on a match.
	for _, e := range nc.Excluded {
		if domainMatches(host, e) {
			return fmt.Errorf("the host %q matches the excluded subtree %q", host, e)
		}
	}
	if len(nc.Permitted) == 0 {
		return nil // no permitted list: everything not excluded is allowed
	}
	for _, p := range nc.Permitted {
		if domainMatches(host, p) {
			return nil
		}
	}
	return fmt.Errorf("the host %q is in none of the permitted subtrees (%s)",
		host, strings.Join(nc.Permitted, ", "))
}

// domainMatches implements RFC 5280 §4.2.1.10 domain semantics, which §6.2.2
// adopts by reference.
//
//	"When the domain name constraint begins with a period, it MAY be expanded
//	with one or more labels. That is, the domain name constraint ".example.com"
//	is satisfied by both host.example.com and my.host.example.com. However, the
//	domain name constraint ".example.com" is not satisfied by "example.com".
//	When the domain name constraint does not begin with a period, it specifies a
//	host."
//
// The excluded case is why the leading-period rule has to be exact. A federation
// that excludes ".east.example.com" has NOT excluded "east.example.com" itself,
// and an implementation that treats the two as the same silently applies a
// constraint nobody wrote.
func domainMatches(host, constraint string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	constraint = strings.ToLower(strings.TrimSuffix(constraint, "."))
	if host == "" || constraint == "" {
		return false
	}
	if strings.HasPrefix(constraint, ".") {
		// A subtree: one or more additional labels, and never the bare domain.
		return strings.HasSuffix(host, constraint)
	}
	// A host: exact.
	return host == constraint
}

// hostOf extracts the host part of an Entity Identifier.
//
// "As in RFC 5280, domain name constraints apply to the host part of the URI."
func hostOf(entityID string) (string, error) {
	u, err := url.Parse(entityID)
	if err != nil {
		return "", fmt.Errorf("the entity identifier %q does not parse as a URL: %w",
			entityID, err)
	}
	h := u.Hostname()
	if h == "" {
		return "", fmt.Errorf("the entity identifier %q has no host", entityID)
	}
	return h, nil
}

// FilterEntityTypes applies §6.2.3 to a subject's metadata.
//
//	"To apply the allowed_entity_types constraint during Trust Chain Resolution
//	all Entity Types that are not listed in the allowed_entity_types constraint
//	MUST be removed from the metadata Claim in the subject's Entity
//	Configuration. The federation_entity Entity Type MUST NOT be removed."
//
// Removal rather than rejection, which is worth noticing: a subject carrying a
// type its superior did not allow does not invalidate the chain, it loses that
// type. An implementation that refuses the chain instead is stricter than the
// specification and breaks federations that are merely untidy.
func FilterEntityTypes(metadata map[string]any, allowed *[]string) map[string]any {
	if allowed == nil {
		return metadata // no constraint: every Entity Type is allowed
	}
	permitted := map[string]bool{FederationEntityType: true}
	for _, t := range *allowed {
		permitted[t] = true
	}
	out := make(map[string]any, len(metadata))
	for k, v := range metadata {
		if permitted[k] {
			out[k] = v
		}
	}
	return out
}

// entityTypeAllowed applies §6.2.3 across a chain.
//
// Each Subordinate Statement's constraint is applied independently, like the
// others: a type must be permitted by EVERY constraint that mentions one, not by
// the nearest or by their union.
//
// federation_entity short-circuits because §6.2.3 exempts it outright -- "The
// federation_entity Entity Type Identifier... is always allowed and MUST NOT be
// included in the constraint" -- so an empty array excludes everything else and
// still permits it.
func entityTypeAllowed(chain []Statement, entityType string) error {
	if entityType == FederationEntityType {
		return nil
	}
	for j := 1; j < len(chain); j++ {
		c := chain[j].Constraints
		if c == nil || c.AllowedEntityTypes == nil {
			continue
		}
		ok := false
		for _, t := range *c.AllowedEntityTypes {
			if t == entityType {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("statement %d (issued by %q) allows only the entity "+
				"type(s) %v, so %q is not available for %q in this chain",
				j, chain[j].Issuer, *c.AllowedEntityTypes, entityType, chain[0].Subject)
		}
	}
	return nil
}
