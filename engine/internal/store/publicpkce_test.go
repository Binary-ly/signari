package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// A public client without PKCE is refused by the schema, whichever writer
// tries (0137). The Admin API and `client set-pkce` refused one, but
// `client create -public -require-pkce=false` made one: a public client holds
// no secret, so the challenge is the only proof the code reached the
// application that asked for it.
func TestAPublicClientWithoutPKCEIsRefusedByTheSchema(t *testing.T) {
	pool := rateTestPool(t)
	ctx := context.Background()
	id := fmt.Sprintf("pkce-probe-%d", time.Now().UnixNano())
	_, err := pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash, require_pkce)
		SELECT $1, id, 'probe', 'public', '', false FROM core.organizations LIMIT 1`, id)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
	})
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.ConstraintName != "clients_public_requires_pkce" {
		t.Fatalf("a public client without PKCE was stored, or refused for another reason: %v", err)
	}
	// A confidential one may opt out: OIDC Basic certification registers such
	// clients, and they authenticate with a secret.
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash, require_pkce)
		SELECT $1, id, 'probe', 'confidential', 'x', false FROM core.organizations LIMIT 1`, id); err != nil {
		t.Fatalf("a confidential client without PKCE was refused: %v", err)
	}
}
