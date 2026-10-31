package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

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
	// Source is where the value comes from, one of MapperSources; empty is
	// attribute. SourceValue is a constant's text, or which of UserFields.
	Source      string
	SourceValue string
	// Transform is lower, prefix or extract, empty for none, and TransformArg
	// the prefix, or the RE2 pattern whose first group, or match, is the value.
	Transform    string
	TransformArg string
}

// MapperSources are what a claim can be made from.
var MapperSources = []string{"attribute", "constant", "groups", "user_field", "relation"}

// UserFields are the fields of a person's record a claim can be made from, and
// the columns they are. Closed, so a mapper cannot be pointed at anything else on
// the row.
var UserFields = map[string]string{"email": "email", "username": "username", "display_name": "display_name",
	"given_name": "given_name", "surname": "surname", "locale": "locale"}

// Key is what makes a mapper the one it is: its audience, destination, and
// attribute, or the claim for a source that has no attribute.
func (m ClaimMapper) Key() string {
	client := m.ClientID
	if client == "" {
		client = "*"
	}
	what := m.Attribute
	if m.Source != "" && m.Source != "attribute" {
		what = m.Source + " as " + m.ClaimName
	}
	return what + " to " + m.Destination + " for " + client
}

// checkSource refuses what could never produce a value.
func (m *ClaimMapper) checkSource() error {
	if m.Source == "" {
		m.Source = "attribute"
	}
	switch m.Source {
	case "attribute", "groups", "relation":
		if m.SourceValue != "" {
			return fmt.Errorf("%w: a %s source takes no value", ErrMapperSource, m.Source)
		}
	case "constant":
		if m.SourceValue == "" {
			return fmt.Errorf("%w: a constant needs its value", ErrMapperSource)
		}
	case "user_field":
		if _, ok := UserFields[m.SourceValue]; !ok {
			return fmt.Errorf("%w: %q is not a field a claim can be made from", ErrMapperSource, m.SourceValue)
		}
	default:
		return fmt.Errorf("%w: the source is one of %s, not %q", ErrMapperSource,
			strings.Join(MapperSources, ", "), m.Source)
	}
	if m.Source != "attribute" && m.Attribute != "" {
		return fmt.Errorf("%w: a %s source names no attribute", ErrMapperSource, m.Source)
	}
	switch m.Transform {
	case "", "lower":
		if m.TransformArg != "" {
			return fmt.Errorf("%w: %q takes no argument", ErrMapperSource, m.Transform)
		}
	case "prefix":
		if m.TransformArg == "" {
			return fmt.Errorf("%w: a prefix needs its text", ErrMapperSource)
		}
	case "extract":
		if len(m.TransformArg) > 256 {
			return fmt.Errorf("%w: a pattern is at most 256 bytes", ErrMapperSource)
		}
		if _, err := regexp.Compile(m.TransformArg); err != nil || m.TransformArg == "" {
			return fmt.Errorf("%w: %q is not an RE2 pattern", ErrMapperSource, m.TransformArg)
		}
	default:
		return fmt.Errorf("%w: the transform is lower, prefix or extract, not %q", ErrMapperSource, m.Transform)
	}
	return nil
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
	// ErrMapperSource is a source or a transform that could not produce a value.
	ErrMapperSource = errors.New("that source or transform cannot produce a value")
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
	if err := m.checkSource(); err != nil {
		return "", false, err
	}
	var attrID any
	var personal bool
	if m.Source == "attribute" {
		var attr string
		if err := tx.QueryRow(ctx, `SELECT id::text, personal FROM core.user_attribute_schema
			WHERE org_id = $1::uuid AND name = $2`, orgID, m.Attribute).Scan(&attr, &personal); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return "", false, fmt.Errorf("%w: %q", ErrMapperAttributeUnknown, m.Attribute)
			}
			return "", false, err
		}
		attrID = attr
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
	conflict := `(org_id, client_id, attribute_id, destination) WHERE attribute_id IS NOT NULL`
	if m.Source != "attribute" {
		conflict = `(org_id, client_id, claim_name, destination) WHERE attribute_id IS NULL`
	}
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO core.claim_mappers (org_id, client_id, attribute_id, claim_name, destination, required_scope,
		                                source, source_value, transform, transform_arg)
		VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT `+conflict+` DO UPDATE SET
			claim_name = EXCLUDED.claim_name, required_scope = EXCLUDED.required_scope,
			source = EXCLUDED.source, source_value = EXCLUDED.source_value,
			transform = EXCLUDED.transform, transform_arg = EXCLUDED.transform_arg
		RETURNING id::text`, orgID, client, attrID, m.ClaimName, m.Destination, m.RequiredScope,
		m.Source, m.SourceValue, m.Transform, m.TransformArg).Scan(&id)
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
		SELECT m.id::text, COALESCE(m.client_id, ''), COALESCE(s.name, ''), COALESCE(s.personal, false), m.claim_name,
		       m.destination, m.required_scope, m.source, m.source_value, m.transform, m.transform_arg
		  FROM core.claim_mappers m LEFT JOIN core.user_attribute_schema s ON s.id = m.attribute_id
		 WHERE m.org_id = $1::uuid
		 ORDER BY s.name, m.claim_name, m.destination, m.client_id NULLS FIRST`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClaimMapper{}
	for rows.Next() {
		var m ClaimMapper
		if err := rows.Scan(&m.ID, &m.ClientID, &m.Attribute, &m.Personal, &m.ClaimName, &m.Destination,
			&m.RequiredScope, &m.Source, &m.SourceValue, &m.Transform, &m.TransformArg); err != nil {
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
