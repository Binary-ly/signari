package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// OpenID Federation 1.0 configuration and keys.
//
// Absent configuration means the instance is not in a federation, and every
// caller here treats that as an ordinary answer rather than an error condition:
// most deployments are not federated, and a missing row is the normal case.

// FederationSettings is what an instance publishes about itself.
type FederationSettings struct {
	// AuthorityHints and TrustAnchorHints are nil for a Trust Anchor with no
	// superiors, and otherwise non-empty -- the database CHECK forbids the
	// empty array, because §3.1.2 does.
	AuthorityHints   []string
	TrustAnchorHints []string
	LifetimeSeconds  int
	OrganizationName string
	HomepageURI      string
	Contacts         []string
}

// FederationConfig reads an instance's federation settings.
//
// Returns an error when there is no row. The caller answers 404, because "this
// entity publishes no configuration" is the honest response — a well-formed but
// contentless Entity Configuration would be signed, and therefore trusted.
func FederationConfig(ctx context.Context, db *pgxpool.Pool, instanceID string) (*FederationSettings, error) {
	var s FederationSettings
	err := db.QueryRow(ctx, `
		SELECT authority_hints, trust_anchor_hints, lifetime_seconds,
		       COALESCE(organization_name,''), COALESCE(homepage_uri,''), contacts
		FROM core.federation_config
		WHERE instance_id = $1::uuid`, instanceID).
		Scan(&s.AuthorityHints, &s.TrustAnchorHints, &s.LifetimeSeconds,
			&s.OrganizationName, &s.HomepageURI, &s.Contacts)
	if err != nil {
		return nil, fmt.Errorf("no federation configuration for this instance: %w", err)
	}
	return &s, nil
}

// FederationJWKS returns the published federation keys as a JWK Set.
//
// Only `active` and `next`. A `passive` key still verifies statements signed
// before the last rotation, but §3.1.1's jwks is what a federation will trust
// for FUTURE verification, and publishing a demoted key there extends its life
// beyond the rotation that ended it.
func FederationJWKS(ctx context.Context, db *pgxpool.Pool, instanceID string) (json.RawMessage, error) {
	rows, err := db.Query(ctx, `
		SELECT public_jwk FROM core.signing_keys
		WHERE instance_id = $1::uuid AND purpose = 'federation'
		  AND state IN ('active', 'next')
		ORDER BY published_at`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := []json.RawMessage{}
	for rows.Next() {
		var jwk json.RawMessage
		if err := rows.Scan(&jwk); err != nil {
			return nil, err
		}
		keys = append(keys, jwk)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("this instance has no federation signing key")
	}
	return json.Marshal(map[string]any{"keys": keys})
}
