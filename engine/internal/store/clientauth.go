package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ClientAuthMethod returns how a client authenticates, and its registered keys.
func ClientAuthMethod(ctx context.Context, db *pgxpool.Pool, clientID string) (method, jwks string, err error) {
	err = db.QueryRow(ctx, `
		SELECT token_endpoint_auth_method, COALESCE(jwks::text,'')
		FROM core.clients WHERE client_id = $1`, clientID).Scan(&method, &jwks)
	return method, jwks, err
}
