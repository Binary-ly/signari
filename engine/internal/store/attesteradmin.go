package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
)

// The Trusted Client Attesters attestation-based client authentication
// verifies against, behind `signari attester` and the Admin API (6.07).

// ErrInvalidAttester is an attester whose key set would fail every
// authentication, or one holding a private key.
var ErrInvalidAttester = errors.New("invalid client attester")

// Attester is one attester an organisation trusts.
type Attester struct {
	Name        string
	Keys        int
	Description string
	CreatedAt   time.Time
}

// SetAttester registers an attester, or replaces its keys; a description left
// empty keeps the one it had.
//
// The key set is parsed before it is stored, and checked for private keys: a
// set that does not parse would fail every authentication at run time with an
// error pointing at the client, and a "public" set holding private keys would
// let this server mint attestations indistinguishable from the attester's,
// which is the separation attestation exists to create.
func SetAttester(ctx context.Context, tx Execer, orgID, name string, jwks []byte, description string) (int, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, fmt.Errorf("%w: it needs a name", ErrInvalidAttester)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(jwks, &set); err != nil {
		return 0, fmt.Errorf("%w: the key set is not a JSON Web Key Set: %v", ErrInvalidAttester, err)
	}
	if len(set.Keys) == 0 {
		return 0, fmt.Errorf("%w: the key set holds no keys", ErrInvalidAttester)
	}
	for i, k := range set.Keys {
		if !k.IsPublic() {
			return 0, fmt.Errorf("%w: key %d is a PRIVATE key; register only the attester's public keys, "+
				"or this server could forge the attestations it is supposed to be verifying", ErrInvalidAttester, i)
		}
		if !k.Valid() {
			return 0, fmt.Errorf("%w: key %d is not usable", ErrInvalidAttester, i)
		}
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO core.client_attesters (org_id, name, jwks, description)
		VALUES ($1::uuid, $2, $3, NULLIF($4, ''))
		ON CONFLICT (org_id, name) DO UPDATE SET jwks = EXCLUDED.jwks,
			description = COALESCE(EXCLUDED.description, client_attesters.description)`,
		orgID, name, jwks, strings.TrimSpace(description))
	return len(set.Keys), err
}

// RemoveAttester stops trusting an attester, reporting whether it was.
func RemoveAttester(ctx context.Context, tx Execer, orgID, name string) (bool, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.client_attesters WHERE org_id = $1::uuid AND name = $2`, orgID, name)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// OrgAttesters lists an organisation's attesters, never their keys.
func OrgAttesters(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) ([]Attester, error) {
	rows, err := q.Query(ctx, `SELECT name, jsonb_array_length(jwks->'keys'), COALESCE(description, ''), created_at
		FROM core.client_attesters WHERE org_id = $1::uuid ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Attester{}
	for rows.Next() {
		var a Attester
		if err := rows.Scan(&a.Name, &a.Keys, &a.Description, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
