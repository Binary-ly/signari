package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/store"
)

// `idp link` makes the link the jwt-bearer grant resolves an assertion's `sub`
// against, for an issuer that is never a sign-in option (2.60); `idp unlink`
// undoes it. The grant's own lookup is what is asserted, not the row.
func TestIdPLinkMakesTheLinkTheAssertionGrantResolves(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)

	var org string
	if err := db.QueryRow(ctx, `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&org); err != nil {
		t.Skipf("no organisation: %v", err)
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	slug, email, sub := "link-"+suffix, "workload-"+suffix+"@example.test", "repo:acme/deploy:"+suffix
	var providerID, userID string
	if err := db.QueryRow(ctx, `
		INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, issuer, jwks_url,
		                                    allow_signup, allow_linking, enabled, allow_jwt_bearer)
		VALUES ($1::uuid, $2, 'link test', 'assertion', '', 'https://issuer.example.test', 'https://issuer.example.test/jwks',
		        false, false, true, true)
		RETURNING id::text`, org, slug).Scan(&providerID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, $2, decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		        md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'))
		RETURNING id::text`, org, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = db.Exec(c, `DELETE FROM core.identity_providers WHERE id = $1::uuid`, providerID)
		_, _ = db.Exec(c, `DELETE FROM core.users WHERE id = $1::uuid`, userID)
	})

	resolves := func() string {
		t.Helper()
		got, _, err := store.FindActiveFederatedUser(ctx, db, providerID, sub)
		if err != nil && !errors.Is(err, store.ErrNoLinkedAccount) && !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		return got
	}
	if got := resolves(); got != "" {
		t.Fatalf("the subject resolved to %s before any link", got)
	}
	if err := run([]string{"idp", "link", "-dsn", dsn, "-slug", slug, "-subject", sub, "-email", email}); err != nil {
		t.Fatal(err)
	}
	if got := resolves(); got != userID {
		t.Fatalf("after idp link the assertion's sub resolves to %q, want %s", got, userID)
	}
	if err := run([]string{"idp", "links", "-dsn", dsn, "-slug", slug}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"idp", "link", "-dsn", dsn, "-slug", slug, "-subject", sub,
		"-email", "nobody-" + suffix + "@example.test"}); err == nil {
		t.Error("a link to a person who does not exist was accepted")
	}
	if err := run([]string{"idp", "unlink", "-dsn", dsn, "-slug", slug, "-subject", sub}); err != nil {
		t.Fatal(err)
	}
	if got := resolves(); got != "" {
		t.Errorf("after idp unlink the subject still resolves to %s", got)
	}
	if err := run([]string{"idp", "unlink", "-dsn", dsn, "-slug", slug, "-subject", sub}); err == nil {
		t.Error("unlinking a subject with no link was accepted")
	}
}
