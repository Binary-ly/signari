package store

import (
	"context"
	"encoding/json"
	"fmt"

	"signari.dev/engine/internal/rar"
)

// RFC 9396 type registration and the details carried with a grant.

// AuthorizationDetailTypes loads the types registered for an organisation,
// optionally narrowed to those a client may request.
//
// The client allow-list is applied HERE rather than after loading, so a type a
// client may not request is never in the registry the validator sees. Validating
// against everything and filtering afterwards would accept the request first and
// remove the permission second, which is the shape that produces a token quietly
// weaker than the consent screen said.
func AuthorizationDetailTypes(ctx context.Context, db Querier, orgID, clientID string) (rar.Registry, error) {
	rows, err := db.Query(ctx, `
		SELECT t.type, t.fields, t.required
		FROM core.authorization_detail_types t
		WHERE t.org_id = $1::uuid
		  AND ($2 = '' OR EXISTS (
		        SELECT 1 FROM core.client_authorization_detail_types c
		        WHERE c.client_id = $2 AND c.type = t.type))`, orgID, clientID)
	if err != nil {
		return nil, fmt.Errorf("loading authorization detail types: %w", err)
	}
	defer rows.Close()

	reg := rar.Registry{}
	for rows.Next() {
		var spec rar.TypeSpec
		if err := rows.Scan(&spec.Type, &spec.Fields, &spec.Required); err != nil {
			return nil, err
		}
		reg[spec.Type] = spec
	}
	return reg, rows.Err()
}

// MarshalDetails renders granted details for storage.
//
// nil for an absent grant rather than an empty array, so the column reads as
// "no rich permissions were requested" instead of "some were requested and none
// survived". Those are different facts and only one of them is a bug.
func MarshalDetails(details []rar.Detail) ([]byte, error) {
	if len(details) == 0 {
		return nil, nil
	}
	return json.Marshal(details)
}

// UnmarshalDetails reads them back.
func UnmarshalDetails(raw []byte) ([]rar.Detail, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []rar.Detail
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("reading stored authorization_details: %w", err)
	}
	return out, nil
}

// AllAuthorizationDetailTypes lists every registered type across the
// deployment, for the discovery document.
//
// Deduplicated and sorted: §10's array is read by clients that cache and compare
// the metadata document, and one that reorders between requests looks like it
// changed. Not scoped to an organisation because discovery is not either — the
// document is served per issuer, and an organisation-specific list would leak
// which tenants exist.
func AllAuthorizationDetailTypes(ctx context.Context, db Querier) ([]string, error) {
	rows, err := db.Query(ctx,
		`SELECT DISTINCT type FROM core.authorization_detail_types ORDER BY type`)
	if err != nil {
		return nil, fmt.Errorf("listing authorization detail types: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
