package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/oidfed"
)

// The entities an instance speaks for in a federation (12.11, §8.1).

// Subordinate is an Immediate Subordinate.
type Subordinate struct {
	EntityID string
	// JWKS are its Federation Entity Keys, as they were given to the operator.
	JWKS json.RawMessage
	// MetadataPolicy is what this entity requires of its metadata; nil for none.
	MetadataPolicy json.RawMessage
	// MaxPathLength limits Intermediates below it (§6.2.1); nil for no limit.
	MaxPathLength *int
	Intermediate  bool
	CreatedAt     time.Time
}

// ErrSubordinateUnknown is an entity this instance does not speak for.
var ErrSubordinateUnknown = errors.New("this instance has no subordinate of that entity id")

// Validate refuses what would be signed into a statement and make it worthless: keys
// that are not keys, private ones above all, and a policy no resolver could apply.
func (sub Subordinate) Validate(self string) error {
	if err := oidfed.ValidateEntityID(sub.EntityID); err != nil {
		return refuse("the entity id: %w", err)
	}
	if sub.EntityID == self {
		return refuse("an entity is not its own subordinate")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(sub.JWKS, &set); err != nil {
		return refuse("the keys are not a JWK Set: %w", err)
	}
	if len(set.Keys) == 0 {
		return refuse("give the keys it signs with, as it gave them to you: a statement with none vouches for nothing")
	}
	for _, k := range set.Keys {
		if !k.IsPublic() {
			return refuse("key %q is a private key, which would be published to everybody who asks", k.KeyID)
		}
		if !k.Valid() {
			return refuse("key %q is not a usable key", k.KeyID)
		}
	}
	if sub.MaxPathLength != nil && *sub.MaxPathLength < 0 {
		return refuse("the path length is a number of Intermediates, which cannot be negative")
	}
	if len(sub.MetadataPolicy) > 0 {
		if err := oidfed.CheckMetadataPolicy(sub.MetadataPolicy); err != nil {
			return refuse("the metadata policy: %w", err)
		}
	}
	return nil
}

// SetSubordinate adds an entity to speak for, or replaces what is said about it.
func SetSubordinate(ctx context.Context, e Execer, instanceID string, sub Subordinate) error {
	var policy any
	if len(sub.MetadataPolicy) > 0 {
		policy = string(sub.MetadataPolicy)
	}
	if _, err := e.Exec(ctx, `
		INSERT INTO core.federation_subordinates (instance_id, entity_id, jwks, metadata_policy, max_path_length, intermediate)
		VALUES ($1::uuid, $2, $3::jsonb, $4::jsonb, $5, $6)
		ON CONFLICT (instance_id, entity_id) DO UPDATE SET jwks = EXCLUDED.jwks,
			metadata_policy = EXCLUDED.metadata_policy, max_path_length = EXCLUDED.max_path_length,
			intermediate = EXCLUDED.intermediate`,
		instanceID, sub.EntityID, string(sub.JWKS), policy, sub.MaxPathLength, sub.Intermediate); err != nil {
		return fmt.Errorf("recording a subordinate: %w", err)
	}
	return nil
}

// RemoveSubordinate stops speaking for an entity, from the next request.
func RemoveSubordinate(ctx context.Context, e Execer, instanceID, entityID string) error {
	tag, err := e.Exec(ctx, `DELETE FROM core.federation_subordinates
		WHERE instance_id = $1::uuid AND entity_id = $2`, instanceID, entityID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSubordinateUnknown
	}
	return nil
}

// Subordinates lists who an instance speaks for, by entity id.
func Subordinates(ctx context.Context, q Querier, instanceID string) ([]Subordinate, error) {
	rows, err := q.Query(ctx, `
		SELECT entity_id, jwks, metadata_policy, max_path_length, intermediate, created_at
		  FROM core.federation_subordinates WHERE instance_id = $1::uuid ORDER BY entity_id`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Subordinate{}
	for rows.Next() {
		var sub Subordinate
		if err := rows.Scan(&sub.EntityID, &sub.JWKS, &sub.MetadataPolicy, &sub.MaxPathLength, &sub.Intermediate,
			&sub.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// SubordinateOf is one of them, or nil.
func SubordinateOf(ctx context.Context, q rowQuerier, instanceID, entityID string) (*Subordinate, error) {
	sub := Subordinate{EntityID: entityID}
	err := q.QueryRow(ctx, `
		SELECT jwks, metadata_policy, max_path_length, intermediate, created_at
		  FROM core.federation_subordinates WHERE instance_id = $1::uuid AND entity_id = $2`, instanceID, entityID).
		Scan(&sub.JWKS, &sub.MetadataPolicy, &sub.MaxPathLength, &sub.Intermediate, &sub.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sub, nil
}

// HasSubordinates reports whether an instance speaks for anybody, which is what makes
// an entity with a superior an Intermediate.
func HasSubordinates(ctx context.Context, q rowQuerier, instanceID string) (bool, error) {
	var has bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.federation_subordinates WHERE instance_id = $1::uuid)`,
		instanceID).Scan(&has)
	return has, err
}
