package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// UMA resource registration (11.12, Federated Authorization §3): what a resource
// server put under this server's protection. The protocol is in internal/httpapi;
// queries are here.

// UMAResource is a resource description (§3.1) as it is held: the resource server
// that registered it, the person it belongs to when a person issued the protection
// API token ("" for the organisation), and the model type it is an object of.
type UMAResource struct {
	ID, OrgID, ClientID, OwnerID string
	Type                         string
	Scopes                       []string
	Name, Description, IconURI   string
	CreatedAt, UpdatedAt         time.Time
}

// ErrUMAResourceUnknown is an id no registration of this resource server and owner
// holds, which §3.2 answers 404 whether it never existed or is another's.
var ErrUMAResourceUnknown = errors.New("no registered resource of that id")

// newUMAResourceID is the id a resource is known by: 128 random bits, since
// knowing one is half of asking for a permission on it.
func newUMAResourceID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

const umaResourceColumns = `id, org_id::text, client_id, COALESCE(owner_id::text, ''), type, scopes,
	COALESCE(name, ''), COALESCE(description, ''), COALESCE(icon_uri, ''), created_at, updated_at`

func scanUMAResource(row pgx.Row) (UMAResource, error) {
	var r UMAResource
	err := row.Scan(&r.ID, &r.OrgID, &r.ClientID, &r.OwnerID, &r.Type, &r.Scopes, &r.Name, &r.Description,
		&r.IconURI, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return UMAResource{}, ErrUMAResourceUnknown
	}
	return r, err
}

// CreateUMAResource registers r and answers the id it is given (§3.2.1).
func CreateUMAResource(ctx context.Context, q rowQuerier, r UMAResource) (string, error) {
	id, err := newUMAResourceID()
	if err != nil {
		return "", err
	}
	if err := q.QueryRow(ctx, `
		INSERT INTO core.uma_resources (id, org_id, client_id, owner_id, type, scopes, name, description, icon_uri)
		VALUES ($1, $2::uuid, $3, NULLIF($4, '')::uuid, $5, $6, NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''))
		RETURNING id`,
		id, r.OrgID, r.ClientID, r.OwnerID, r.Type, r.Scopes, r.Name, r.Description, r.IconURI).Scan(&id); err != nil {
		return "", fmt.Errorf("registering a resource: %w", err)
	}
	return id, nil
}

// UMAResourceOf is one of the resources clientID registered for ownerID ("" for the
// organisation): the only ones a protection API token may read, replace or delete.
func UMAResourceOf(ctx context.Context, q rowQuerier, id, clientID, ownerID string) (UMAResource, error) {
	return scanUMAResource(q.QueryRow(ctx, `SELECT `+umaResourceColumns+` FROM core.uma_resources
		WHERE id = $1 AND client_id = $2 AND owner_id IS NOT DISTINCT FROM NULLIF($3, '')::uuid`, id, clientID, ownerID))
}

// RegisteredUMAResource is the resource id names, whoever registered it, for the
// permission endpoint to hold to its resource server and owner.
func RegisteredUMAResource(ctx context.Context, q rowQuerier, id string) (UMAResource, error) {
	return scanUMAResource(q.QueryRow(ctx, `SELECT `+umaResourceColumns+` FROM core.uma_resources WHERE id = $1`, id))
}

// ReplaceUMAResource replaces a description whole (§3.2.3): what the update does not
// say is gone, as a PUT means. Its type is kept, since the relations granted on it
// are on an object of that type.
func ReplaceUMAResource(ctx context.Context, q Execer, r UMAResource) error {
	tag, err := q.Exec(ctx, `
		UPDATE core.uma_resources SET scopes = $4, name = NULLIF($5, ''), description = NULLIF($6, ''),
		       icon_uri = NULLIF($7, ''), updated_at = now()
		 WHERE id = $1 AND client_id = $2 AND owner_id IS NOT DISTINCT FROM NULLIF($3, '')::uuid`,
		r.ID, r.ClientID, r.OwnerID, r.Scopes, r.Name, r.Description, r.IconURI)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUMAResourceUnknown
	}
	return nil
}

// DeleteUMAResource deregisters a resource (§3.2.4), and with it every relation
// granted on it, in one transaction: protection "ends on successful deregistration",
// and a share left on an object nobody can ask about is a grant waiting for an id
// to be reused.
func DeleteUMAResource(ctx context.Context, tx pgx.Tx, id, clientID, ownerID string) error {
	var orgID, typ string
	err := tx.QueryRow(ctx, `
		DELETE FROM core.uma_resources
		 WHERE id = $1 AND client_id = $2 AND owner_id IS NOT DISTINCT FROM NULLIF($3, '')::uuid
		RETURNING org_id::text, type`, id, clientID, ownerID).Scan(&orgID, &typ)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUMAResourceUnknown
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `DELETE FROM core.relations WHERE org_id = $1::uuid AND object_type = $2 AND object_id = $3`,
		orgID, typ, id)
	return err
}

// ListUMAResources is the ids clientID registered for ownerID (§3.2.5).
func ListUMAResources(ctx context.Context, q Querier, clientID, ownerID string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT id FROM core.uma_resources
		WHERE client_id = $1 AND owner_id IS NOT DISTINCT FROM NULLIF($2, '')::uuid ORDER BY created_at, id`,
		clientID, ownerID)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if ids == nil {
		ids = []string{}
	}
	return ids, err
}

// UMAResourcesOwnedBy is what a person owns, for the page they share it from.
func UMAResourcesOwnedBy(ctx context.Context, q Querier, userID string) ([]UMAResource, error) {
	rows, err := q.Query(ctx, `SELECT `+umaResourceColumns+` FROM core.uma_resources
		WHERE owner_id = $1::uuid ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UMAResource
	for rows.Next() {
		r, err := scanUMAResource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
