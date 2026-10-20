package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"signari.dev/engine/internal/oauth"
)

// The resource servers an organisation's access tokens may be audienced to
// (0157). See the migration for why a requested resource must be one of them.

// ErrResourceServerUnknown is a removal naming a resource nobody registered.
var ErrResourceServerUnknown = errors.New("no such resource server")

// ResourceServer is one registered resource indicator.
type ResourceServer struct {
	Resource string `json:"resource"`
	Name     string `json:"name"`
}

// UnregisteredResource returns the first of resources that orgID has not
// registered, or "" when every one is registered. An empty list asks nothing.
func UnregisteredResource(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string, resources []string) (string, error) {
	if len(resources) == 0 {
		return "", nil
	}
	var missing *string
	if err := q.QueryRow(ctx, `
		SELECT r FROM unnest($2::text[]) WITH ORDINALITY AS u(r, n)
		WHERE NOT EXISTS (SELECT 1 FROM core.resource_servers
		                  WHERE org_id = $1::uuid AND resource = u.r)
		ORDER BY n LIMIT 1`, orgID, resources).Scan(&missing); err != nil &&
		!errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("checking resource indicators: %w", err)
	}
	if missing == nil {
		return "", nil
	}
	return *missing, nil
}

// SetResourceServer registers a resource, or renames one already registered.
func SetResourceServer(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, orgID, resource, name string) error {
	if err := oauth.CheckResource(resource); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO core.resource_servers (org_id, resource, name)
		VALUES ($1::uuid, $2, $3)
		ON CONFLICT (org_id, resource) DO UPDATE SET name = EXCLUDED.name`,
		orgID, resource, name); err != nil {
		return fmt.Errorf("registering the resource server: %w", err)
	}
	return nil
}

// RemoveResourceServer withdraws a resource. Tokens for it are refused from the
// next request, including refreshes of tokens already issued.
func RemoveResourceServer(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, orgID, resource string) error {
	tag, err := q.Exec(ctx, `DELETE FROM core.resource_servers
		WHERE org_id = $1::uuid AND resource = $2`, orgID, resource)
	if err != nil {
		return fmt.Errorf("removing the resource server: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrResourceServerUnknown
	}
	return nil
}

// ResourceServers lists an organisation's registered resources.
func ResourceServers(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) ([]ResourceServer, error) {
	rows, err := q.Query(ctx, `SELECT resource, name FROM core.resource_servers
		WHERE org_id = $1::uuid ORDER BY resource`, orgID)
	if err != nil {
		return nil, fmt.Errorf("listing resource servers: %w", err)
	}
	defer rows.Close()
	out := []ResourceServer{}
	for rows.Next() {
		var rs ResourceServer
		if err := rows.Scan(&rs.Resource, &rs.Name); err != nil {
			return nil, err
		}
		out = append(out, rs)
	}
	return out, rows.Err()
}
