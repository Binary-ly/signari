package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// An identity provider's slug is its sign-in URL -- /login/with/<slug> -- and
// the URL names no organisation. Unique per organisation and looked up
// globally, a second organisation registering the same slug made the route
// answer with either row, sending some of the first organisation's people
// through the second's upstream configuration and into its accounts.
func TestASlugCannotBeTakenByASecondOrganisation(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()
	orgA, _, _, _ := fixture(t, conn)
	orgB, _, _, _ := fixture(t, conn)

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	slug := fmt.Sprintf("google-%d", time.Now().UnixNano())
	insert := func(org string) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO core.identity_providers
				(org_id, slug, display_name, kind, client_id, scopes)
			VALUES ($1::uuid, $2, 'Google', 'oidc', 'client', '{openid}')`, org, slug)
		return err
	}
	if err := insert(orgA); err != nil {
		t.Fatal(err)
	}

	if _, err := tx.Exec(ctx, `SAVEPOINT second`); err != nil {
		t.Fatal(err)
	}
	err = insert(orgB)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23505" || pg.ConstraintName != "identity_providers_slug_key" {
		t.Fatalf("a second organisation registered slug %q (err %v); the sign-in route would "+
			"answer with either organisation's provider", slug, err)
	}
	if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT second`); err != nil {
		t.Fatal(err)
	}

	// And within one organisation, as before.
	if err := insert(orgA); err == nil {
		t.Fatal("the same organisation registered one slug twice")
	}
}
