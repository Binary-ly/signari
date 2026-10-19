package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// `idp trust-mfa` writes the lists a federated sign-in is read against, clears
// them when given neither, and refuses a provider that sends no ID token, where
// the setting would govern nothing (2.13).
func TestIdPTrustMFAWritesWhatTheSignInReads(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) }) // after the delete below

	var org string
	if err := db.QueryRow(ctx, `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&org); err != nil {
		t.Skipf("no organisation to register a provider in: %v", err)
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	oidc, github := "mfa-oidc-"+suffix, "mfa-github-"+suffix
	for slug, kind := range map[string]string{oidc: "oidc", github: "github"} {
		if _, err := db.Exec(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id)
			VALUES ($1::uuid, $2, 'trust-mfa test', $3, 'signari')`, org, slug, kind); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM core.identity_providers WHERE slug = ANY($1)`,
			[]string{oidc, github})
	})

	lists := func(slug string) (amr, acr []string) {
		t.Helper()
		if err := db.QueryRow(ctx, `SELECT mfa_amr, mfa_acr FROM core.identity_providers WHERE slug = $1`,
			slug).Scan(&amr, &acr); err != nil {
			t.Fatal(err)
		}
		return
	}
	trust := func(slug string, args ...string) error {
		return run(append([]string{"idp", "trust-mfa", "-dsn", dsn, "-slug", slug}, args...))
	}

	if err := trust(oidc, "-upstream-amr", "mfa,hwk", "-upstream-acr", "urn:example:multi"); err != nil {
		t.Fatal(err)
	}
	if amr, acr := lists(oidc); !slices.Equal(amr, []string{"mfa", "hwk"}) || !slices.Equal(acr, []string{"urn:example:multi"}) {
		t.Fatalf("after trusting: amr %v, acr %v", amr, acr)
	}
	if err := trust(oidc); err != nil {
		t.Fatal(err)
	}
	if amr, acr := lists(oidc); len(amr)+len(acr) != 0 {
		t.Fatalf("given neither list, the provider still trusts amr %v, acr %v", amr, acr)
	}

	if err := trust(github, "-upstream-amr", "mfa"); err == nil {
		t.Error("a GitHub provider, which sends no ID token, was given an amr to trust")
	}
	if amr, _ := lists(github); len(amr) != 0 {
		t.Errorf("the refused GitHub provider trusts %v", amr)
	}
	if err := trust("no-such-provider-" + suffix); err == nil {
		t.Error("an unknown slug was accepted")
	}
}
