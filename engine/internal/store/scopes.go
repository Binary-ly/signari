package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Scopes an organisation has declared.
//
// See migration 0115 for why these are objects rather than strings: a scope
// used to exist because the same word was typed into a client's registered
// list and a claim mapper's `required_scope`, with nothing connecting them.

// Scope is one declared scope.
type Scope struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
	Advertise   bool   `json:"advertise"`
}

// StandardScopes are defined by the specifications and are not rows.
//
// Exported so the discovery document and the declaration path agree on the set
// without either holding its own copy.
var StandardScopes = []string{
	"openid", "profile", "email", "groups", "offline_access",
}

// IsStandardScope reports whether a name belongs to the fixed set.
func IsStandardScope(name string) bool {
	for _, s := range StandardScopes {
		if s == name {
			return true
		}
	}
	return false
}

// Scopes returns an organisation's declarations.
func Scopes(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) ([]Scope, error) {
	rows, err := q.Query(ctx, `
		SELECT name, display_name, description, advertise
		FROM core.scopes WHERE org_id = $1::uuid ORDER BY name`, orgID)
	if err != nil {
		return nil, fmt.Errorf("listing scopes: %w", err)
	}
	defer rows.Close()

	out := []Scope{}
	for rows.Next() {
		var s Scope
		if err := rows.Scan(&s.Name, &s.DisplayName, &s.Description, &s.Advertise); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// AdvertisedScopes returns the scope names a discovery document should list.
//
// The standard set always, plus this organisation's declarations that asked to
// be advertised. An instance with no organisations, or a query that fails, still
// yields the standard set — discovery must not become unanswerable because an
// optional catalogue could not be read.
func AdvertisedScopes(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) []string {
	out := make([]string, len(StandardScopes))
	copy(out, StandardScopes)
	if orgID == "" {
		return out
	}
	rows, err := q.Query(ctx, `
		SELECT name FROM core.scopes
		WHERE org_id = $1::uuid AND advertise ORDER BY name`, orgID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return out
		}
		out = append(out, name)
	}
	return out
}

// DescribeScopes returns a description for each requested scope, for consent.
//
// Unknown scopes are returned with an empty description rather than dropped. A
// consent screen that silently omitted a scope the client asked for would show
// a person less than they are being asked to agree to, which is the one thing
// that screen must never do.
func DescribeScopes(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string, requested []string) map[string]Scope {
	out := make(map[string]Scope, len(requested))
	for _, name := range requested {
		out[name] = Scope{Name: name}
	}
	if orgID == "" || len(requested) == 0 {
		return out
	}
	rows, err := q.Query(ctx, `
		SELECT name, display_name, description, advertise
		FROM core.scopes WHERE org_id = $1::uuid AND name = ANY($2)`, orgID, requested)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var s Scope
		if err := rows.Scan(&s.Name, &s.DisplayName, &s.Description, &s.Advertise); err != nil {
			return out
		}
		out[s.Name] = s
	}
	return out
}

// DeclareScope creates or updates a scope declaration.
func DeclareScope(ctx context.Context, tx pgx.Tx, orgID string, s Scope) error {
	if IsStandardScope(s.Name) {
		// Refused here as well as by the CHECK, so the error names the reason
		// rather than a constraint. A row appearing to redefine `email` would be
		// a configuration surface over behaviour that lives in code: an operator
		// could rewrite its description and change nothing.
		return fmt.Errorf("%q is a standard scope; its meaning is defined by the "+
			"specification and is not configurable", s.Name)
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO core.scopes (org_id, name, display_name, description, advertise)
		VALUES ($1::uuid, $2, $3, $4, $5)
		ON CONFLICT (org_id, name) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			description  = EXCLUDED.description,
			advertise    = EXCLUDED.advertise,
			updated_at   = now()`,
		orgID, s.Name, s.DisplayName, s.Description, s.Advertise)
	if err != nil {
		return fmt.Errorf("declaring scope %q: %w", s.Name, err)
	}
	return nil
}

// UndeclaredScopes returns the requested names that are neither standard nor
// declared for this organisation.
//
// Used when REGISTERING a client, not when handling a request: the request-time
// gate is Client.UnknownScopes, which was already there. This one catches the
// typo at the moment it is made, which is the difference between a mapper that
// never fires and an error message.
func UndeclaredScopes(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string, requested []string) ([]string, error) {
	var candidates []string
	for _, name := range requested {
		if !IsStandardScope(name) {
			candidates = append(candidates, name)
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	declared := map[string]bool{}
	rows, err := q.Query(ctx, `
		SELECT name FROM core.scopes WHERE org_id = $1::uuid AND name = ANY($2)`,
		orgID, candidates)
	if err != nil {
		return nil, fmt.Errorf("checking declared scopes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		declared[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var out []string
	for _, name := range candidates {
		if !declared[name] {
			out = append(out, name)
		}
	}
	return out, nil
}
