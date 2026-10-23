package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// The writes behind `signari rar` and the Admin API's authorization details
// routes (6.07), one implementation for both.

// RARCommonFields are RFC 9396 §2.2's common data fields, the only ones a
// type may use: a field outside them cannot be validated, and this server
// refuses any field it cannot validate.
var RARCommonFields = []string{"locations", "actions", "datatypes", "identifier", "privileges"}

// ErrInvalidDetailType is a type that could never be granted as registered,
// or one a client asks for that its organisation never registered.
var ErrInvalidDetailType = errors.New("invalid authorization details type")

// DetailType is one RFC 9396 authorization details type an organisation
// accepts, and the clients that may ask for it.
type DetailType struct {
	Type        string
	Fields      []string
	Required    []string
	Description string
	Clients     []string
}

// RegisterDetailType records a type, or replaces its fields.
func RegisterDetailType(ctx context.Context, tx Execer, orgID string, t DetailType) error {
	t.Type = strings.TrimSpace(t.Type)
	if t.Type == "" {
		return fmt.Errorf("%w: a type needs the identifier clients send in authorization_details", ErrInvalidDetailType)
	}
	if len(t.Fields) == 0 {
		return fmt.Errorf("%w: a type with no fields carries no permission and could only ever "+
			"authorise nothing; name some of %s", ErrInvalidDetailType, strings.Join(RARCommonFields, ", "))
	}
	for _, f := range append(append([]string{}, t.Fields...), t.Required...) {
		if !slices.Contains(RARCommonFields, f) {
			return fmt.Errorf("%w: %q is not one of RFC 9396 section 2.2's common data fields (%s)",
				ErrInvalidDetailType, f, strings.Join(RARCommonFields, ", "))
		}
	}
	for _, f := range t.Required {
		if !slices.Contains(t.Fields, f) {
			return fmt.Errorf("%w: %q is required and not one of the fields, so the type could never "+
				"be satisfied", ErrInvalidDetailType, f)
		}
	}
	if t.Required == nil {
		t.Required = []string{}
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO core.authorization_detail_types (org_id, type, fields, required, description)
		VALUES ($1::uuid, $2, $3, $4, NULLIF($5,''))
		ON CONFLICT (org_id, type) DO UPDATE
		SET fields = EXCLUDED.fields, required = EXCLUDED.required, description = EXCLUDED.description`,
		orgID, t.Type, t.Fields, t.Required, t.Description)
	return err
}

// RemoveDetailType forgets a type and every client's leave to ask for it,
// reporting whether the organisation had it.
func RemoveDetailType(ctx context.Context, tx Execer, orgID, typ string) (bool, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.authorization_detail_types WHERE org_id = $1::uuid AND type = $2`,
		orgID, typ)
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.client_authorization_detail_types
		WHERE org_id = $1::uuid AND type = $2`, orgID, typ); err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// OrgDetailTypes lists an organisation's types and who may ask for each.
func OrgDetailTypes(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) ([]DetailType, error) {
	rows, err := q.Query(ctx, `
		SELECT t.type, t.fields, t.required, COALESCE(t.description, ''),
		       COALESCE(array_agg(c.client_id ORDER BY c.client_id) FILTER (WHERE c.client_id IS NOT NULL), '{}')
		  FROM core.authorization_detail_types t
		  LEFT JOIN core.client_authorization_detail_types c ON c.org_id = t.org_id AND c.type = t.type
		 WHERE t.org_id = $1::uuid
		 GROUP BY t.type, t.fields, t.required, t.description
		 ORDER BY t.type`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DetailType{}
	for rows.Next() {
		var t DetailType
		if err := rows.Scan(&t.Type, &t.Fields, &t.Required, &t.Description, &t.Clients); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetClientDetailTypes replaces the types a client may ask for, each one its
// organisation registered.
func SetClientDetailTypes(ctx context.Context, tx interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Execer
}, clientID string, types []string) error {
	var orgID string
	if err := tx.QueryRow(ctx, `SELECT org_id::text FROM core.clients WHERE client_id = $1`, clientID).
		Scan(&orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrClientNotFound
		}
		return err
	}
	if types == nil {
		types = []string{}
	}
	var missing []string
	if err := tx.QueryRow(ctx, `SELECT coalesce(array_agg(n ORDER BY n), '{}') FROM unnest($2::text[]) n
		WHERE NOT EXISTS (SELECT 1 FROM core.authorization_detail_types t WHERE t.org_id = $1::uuid AND t.type = n)`,
		orgID, types).Scan(&missing); err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: the client's organisation registered no type %s", ErrInvalidDetailType,
			strings.Join(missing, ", "))
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.client_authorization_detail_types WHERE client_id = $1`,
		clientID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO core.client_authorization_detail_types (client_id, org_id, type)
		SELECT $1, $2::uuid, n FROM unnest($3::text[]) n ON CONFLICT DO NOTHING`, clientID, orgID, types)
	return err
}

// AllowClientDetailType lets a client ask for one more type, which its own
// organisation registered. It found the type in whichever organisation came
// back first, so a type two organisations registered was refused for one of
// them as belonging to another (0.32).
func AllowClientDetailType(ctx context.Context, tx interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Execer
}, clientID, typ string) error {
	tag, err := tx.Exec(ctx, `
		INSERT INTO core.client_authorization_detail_types (client_id, org_id, type)
		SELECT c.client_id, c.org_id, t.type FROM core.clients c
		  JOIN core.authorization_detail_types t ON t.org_id = c.org_id AND t.type = $2
		 WHERE c.client_id = $1
		ON CONFLICT DO NOTHING`, clientID, typ)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	var known, allowed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.clients WHERE client_id = $1),
		EXISTS (SELECT 1 FROM core.client_authorization_detail_types WHERE client_id = $1 AND type = $2)`,
		clientID, typ).Scan(&known, &allowed); err != nil {
		return err
	}
	switch {
	case !known:
		return ErrClientNotFound
	case allowed:
		return nil
	}
	return fmt.Errorf("%w: the client's organisation registered no type %q", ErrInvalidDetailType, typ)
}

// ClientDetailTypes are the types a client may ask for.
func ClientDetailTypes(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, clientID string) ([]string, error) {
	var out []string
	err := q.QueryRow(ctx, `SELECT COALESCE(array_agg(type ORDER BY type), '{}')
		FROM core.client_authorization_detail_types WHERE client_id = $1`, clientID).Scan(&out)
	return out, err
}
