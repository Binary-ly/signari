package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// A user attribute released as a claim (0113), as the Admin API and a
// configuration file declare it (6.19), one implementation for both. Creating
// one is a disclosure decision: it decides that one relying party, or every
// one, receives a fact about every person who has it.

// ClaimMapper is one attribute released as one claim to one audience.
type ClaimMapper struct {
	ID          string
	Attribute   string
	ClaimName   string
	Destination string // id_token, userinfo or access_token
	// ClientID empty is every client in the organisation, the wider
	// disclosure, which a caller states rather than defaults to.
	ClientID      string
	RequiredScope string
	// Personal is whether the attribute released is, read back.
	Personal bool
}

var (
	// ErrMapperAttributeUnknown is an attribute the organisation did not declare.
	ErrMapperAttributeUnknown = errors.New("no attribute of that name is declared")
	// ErrMapperScopeUnknown is a required scope neither standard nor declared,
	// which no grant can carry, so the mapper would release nothing.
	ErrMapperScopeUnknown = errors.New("the required scope is neither a standard scope nor declared")
	// ErrMapperClientElsewhere is a client that is not the organisation's,
	// which is never issued this organisation's tokens.
	ErrMapperClientElsewhere = errors.New("the client is not this organisation's")
	// ErrMapperProtocolClaim is a claim name that is part of the token's own
	// identity: sub, iss, aud, acr, amr and the rest.
	ErrMapperProtocolClaim = errors.New("that claim name is part of the token's own identity")
	// ErrMapperDestination is a destination other than id_token, userinfo
	// and access_token.
	ErrMapperDestination = errors.New("the destination is id_token, userinfo or access_token")
	// ErrMapperUnknown is a mapper removed that does not exist.
	ErrMapperUnknown = errors.New("no such claim mapper")
)

// SetClaimMapper declares a mapper, replacing the one for the same client (or
// every client), attribute and destination, and answers its id and whether
// the attribute is personal.
func SetClaimMapper(ctx context.Context, tx pgx.Tx, orgID string, m ClaimMapper) (string, bool, error) {
	switch m.Destination {
	case "id_token", "userinfo", "access_token":
	default:
		return "", false, ErrMapperDestination
	}
	var attrID string
	var personal bool
	if err := tx.QueryRow(ctx, `SELECT id::text, personal FROM core.user_attribute_schema
		WHERE org_id = $1::uuid AND name = $2`, orgID, m.Attribute).Scan(&attrID, &personal); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, fmt.Errorf("%w: %q", ErrMapperAttributeUnknown, m.Attribute)
		}
		return "", false, err
	}
	// Share-locked, so a delete of the declaration waits for this and then
	// finds the mapper.
	if m.RequiredScope != "" && !IsStandardScope(m.RequiredScope) {
		var declared bool
		if err := tx.QueryRow(ctx, `SELECT true FROM core.scopes WHERE org_id = $1::uuid AND name = $2 FOR SHARE`,
			orgID, m.RequiredScope).Scan(&declared); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return "", false, fmt.Errorf("%w: %q", ErrMapperScopeUnknown, m.RequiredScope)
			}
			return "", false, err
		}
	}
	var client any
	if m.ClientID != "" {
		var clientOrg string
		if err := tx.QueryRow(ctx, `SELECT org_id::text FROM core.clients WHERE client_id = $1`, m.ClientID).
			Scan(&clientOrg); errors.Is(err, pgx.ErrNoRows) || (err == nil && clientOrg != orgID) {
			return "", false, fmt.Errorf("%w: %q", ErrMapperClientElsewhere, m.ClientID)
		} else if err != nil {
			return "", false, err
		}
		client = m.ClientID
	}
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO core.claim_mappers (org_id, client_id, attribute_id, claim_name, destination, required_scope)
		VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6)
		ON CONFLICT (org_id, client_id, attribute_id, destination) DO UPDATE SET
			claim_name = EXCLUDED.claim_name, required_scope = EXCLUDED.required_scope
		RETURNING id::text`, orgID, client, attrID, m.ClaimName, m.Destination, m.RequiredScope).Scan(&id)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.ConstraintName == "claim_mappers_not_a_protocol_claim" {
		return "", false, fmt.Errorf("%w: %q", ErrMapperProtocolClaim, m.ClaimName)
	}
	if err != nil {
		return "", false, fmt.Errorf("declaring the claim mapper: %w", err)
	}
	return id, personal, nil
}

// ClaimMappers lists what an organisation releases, and to whom.
func ClaimMappers(ctx context.Context, q Querier, orgID string) ([]ClaimMapper, error) {
	rows, err := q.Query(ctx, `
		SELECT m.id::text, COALESCE(m.client_id, ''), s.name, s.personal, m.claim_name, m.destination,
		       m.required_scope
		  FROM core.claim_mappers m JOIN core.user_attribute_schema s ON s.id = m.attribute_id
		 WHERE m.org_id = $1::uuid
		 ORDER BY s.name, m.destination, m.client_id NULLS FIRST`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClaimMapper{}
	for rows.Next() {
		var m ClaimMapper
		if err := rows.Scan(&m.ID, &m.ClientID, &m.Attribute, &m.Personal, &m.ClaimName, &m.Destination,
			&m.RequiredScope); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// RemoveClaimMapper stops a mapper releasing anything, by its id, in the
// organisation only, so a caller cannot remove another tenant's by guessing.
func RemoveClaimMapper(ctx context.Context, q Execer, orgID, id string) error {
	tag, err := q.Exec(ctx, `DELETE FROM core.claim_mappers WHERE id = $1::uuid AND org_id = $2::uuid`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrMapperUnknown
	}
	return nil
}
