package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"signari.dev/engine/internal/oauth"
)

// The resource servers an organisation's access tokens may be audienced to
// (0157). See the migration for why a requested resource must be one of them.

// ErrResourceServerUnknown is a removal naming a resource nobody registered.
var ErrResourceServerUnknown = errors.New("no such resource server")

// ResourceMetadataPath is where a registered resource's RFC 9728 document is
// published, under the issuer and before its id.
const ResourceMetadataPath = "/.well-known/oauth-protected-resource/resources/"

// ResourceServer is one registered resource indicator.
type ResourceServer struct {
	Resource string `json:"resource"`
	Name     string `json:"name"`
	// Scopes is what its metadata tells a client to ask for, and decides nothing.
	Scopes []string `json:"scopes"`
	// MetadataURL is for the resource to name in its 401.
	MetadataURL string `json:"metadata_url"`
}

// ResourceMetadata is the resource an id published by MetadataURL names, in instanceID,
// or nil. An id that is not one names nothing: it comes from a stranger's request.
func ResourceMetadata(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id, instanceID string) (*ResourceServer, error) {
	if !uuidShaped(id) {
		return nil, nil
	}
	var rs ResourceServer
	err := q.QueryRow(ctx, `
		SELECT resource, name, scopes FROM core.resource_servers
		 WHERE id = $1::uuid AND `+InInstance("org_id", "$2"), id, instanceID).Scan(&rs.Resource, &rs.Name, &rs.Scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading a resource's metadata: %w", err)
	}
	return &rs, nil
}

func uuidShaped(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case !strings.ContainsRune("0123456789abcdefABCDEF", c):
			return false
		}
	}
	return true
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

// SetResourceServer registers a resource, or renames one already registered. Nil
// scopes leaves what it has, since most callers are naming it and not describing it.
func SetResourceServer(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, orgID, resource, name string, scopes []string) error {
	if err := oauth.CheckResource(resource); err != nil {
		return err
	}
	for _, s := range scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n\"\\") {
			return fmt.Errorf("%w: %q", ErrResourceScope, s)
		}
	}
	// Never an instance's Admin API audience (tokens.AdminAudience, 6.01):
	// registered as an organisation's own resource, its clients' ordinary
	// tokens would be audienced to the Admin API.
	tag, err := q.Exec(ctx, `
		INSERT INTO core.resource_servers (org_id, resource, name, scopes)
		SELECT $1::uuid, $2, $3, COALESCE($4::text[], '{}')
		 WHERE NOT EXISTS (SELECT 1 FROM core.instances WHERE rtrim(issuer, '/') || '/admin' = $2)
		ON CONFLICT (org_id, resource) DO UPDATE SET name = EXCLUDED.name,
			scopes = COALESCE($4::text[], core.resource_servers.scopes)`,
		orgID, resource, name, scopes)
	if err != nil {
		return fmt.Errorf("registering the resource server: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrResourceIsAdminAPI
	}
	return nil
}

// ErrResourceScope is a scope RFC 6749 §3.3's grammar has no room for.
var ErrResourceScope = errors.New("a scope is one word, with no quote or backslash")

// ErrResourceIsAdminAPI is a resource server named as the Admin API's audience.
var ErrResourceIsAdminAPI = errors.New("that is this deployment's Admin API audience, which no organisation registers as a resource server")

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
	rows, err := q.Query(ctx, `
		SELECT r.resource, r.name, r.scopes, rtrim(i.issuer, '/') || $2 || r.id::text
		  FROM core.resource_servers r
		  JOIN core.organizations o ON o.id = r.org_id
		  JOIN core.instances i ON i.id = o.instance_id
		 WHERE r.org_id = $1::uuid ORDER BY r.resource`, orgID, ResourceMetadataPath)
	if err != nil {
		return nil, fmt.Errorf("listing resource servers: %w", err)
	}
	defer rows.Close()
	out := []ResourceServer{}
	for rows.Next() {
		var rs ResourceServer
		if err := rows.Scan(&rs.Resource, &rs.Name, &rs.Scopes, &rs.MetadataURL); err != nil {
			return nil, err
		}
		out = append(out, rs)
	}
	return out, rows.Err()
}
