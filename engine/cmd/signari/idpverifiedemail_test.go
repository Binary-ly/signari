package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/store"
)

// `idp verified-email` changes the policy the sign-in loads, each flag the
// setting it names and nothing else (0.36). Its trust flag once wrote
// require_verified_email, so turning belief in email_verified off left a
// generic provider believed and required verified addresses instead.
func TestIdPVerifiedEmailWritesWhatTheSignInReads(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close) // after the delete below

	var org string
	if err := db.QueryRow(ctx, `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&org); err != nil {
		t.Skipf("no organisation to register a provider in: %v", err)
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	oidc, google := "email-oidc-"+suffix, "email-google-"+suffix
	for slug, kind := range map[string]string{oidc: "oidc", google: "google"} {
		if _, err := db.Exec(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id,
			trust_email_verification) VALUES ($1::uuid, $2, 'verified-email test', $3, 'signari', $3 = 'oidc')`,
			org, slug, kind); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM core.identity_providers WHERE slug = ANY($1)`,
			[]string{oidc, google})
	})

	policy := func() (trusts, requires bool) {
		t.Helper()
		p, err := store.LoadIdentityProvider(ctx, db, nil, oidc)
		if err != nil {
			t.Fatal(err)
		}
		return p.Policy.TrustsEmailVerification, p.Policy.RequireVerifiedEmail
	}
	verified := func(slug string, args ...string) error {
		return run(append([]string{"idp", "verified-email", "-dsn", dsn, "-slug", slug}, args...))
	}

	if trusts, requires := policy(); !trusts || !requires {
		t.Fatalf("registered believing and requiring, the sign-in reads trusts %v, requires %v", trusts, requires)
	}
	if err := verified(oidc, "-trust-email-verification=false"); err != nil {
		t.Fatal(err)
	}
	if trusts, requires := policy(); trusts || !requires {
		t.Errorf("after -trust-email-verification=false the sign-in reads trusts %v, requires %v", trusts, requires)
	}
	if err := verified(oidc, "-require-verified-email=false"); err != nil {
		t.Fatal(err)
	}
	if trusts, requires := policy(); trusts || requires {
		t.Errorf("after -require-verified-email=false the sign-in reads trusts %v, requires %v", trusts, requires)
	}
	if err := verified(oidc, "-trust-email-verification", "-require-verified-email"); err != nil {
		t.Fatal(err)
	}
	if trusts, requires := policy(); !trusts || !requires {
		t.Errorf("after both the sign-in reads trusts %v, requires %v", trusts, requires)
	}

	if err := verified(oidc); err == nil {
		t.Error("given neither flag, the command changed nothing and said nothing")
	}
	// A named provider's belief is its preset's, so a setting here would be
	// read by nothing.
	if err := verified(google, "-trust-email-verification=false"); err == nil {
		t.Error("a Google provider was told what to believe of its own email_verified")
	}
	if err := verified(google, "-require-verified-email=false"); err != nil {
		t.Errorf("a Google provider's sign-ups: %v", err)
	}
}
