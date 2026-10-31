package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ClientJWKS returns the keys a client registered. Read when an assertion is to
// be checked against them, and not with the client, whose every other use has no
// need of a document that size.
func ClientJWKS(ctx context.Context, db *pgxpool.Pool, clientID string) (string, error) {
	var jwks string
	err := db.QueryRow(ctx, `SELECT COALESCE(jwks::text, '') FROM core.clients WHERE client_id = $1`, clientID).Scan(&jwks)
	return jwks, err
}
