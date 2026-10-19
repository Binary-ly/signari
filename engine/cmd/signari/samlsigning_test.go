package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// `saml signing` changes only the flags it is given (2.05). It wrote both every
// time, so setting a lifetime turned Response signing off again, and a provider
// that requires a signed Response refused every sign-in from then on.
func TestSAMLSigningChangesOnlyWhatItIsGiven(t *testing.T) {
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
	entity := fmt.Sprintf("https://saml-signing-%d.test", time.Now().UnixNano())
	if _, err := db.Exec(ctx, `INSERT INTO core.saml_providers (org_id, entity_id, display_name)
		VALUES ($1::uuid, $2, 'signing test')`, org, entity); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM core.saml_providers WHERE entity_id = $1`, entity)
	})

	state := func() (assertions, responses bool, lifetime int) {
		t.Helper()
		if err := db.QueryRow(ctx, `SELECT sign_assertions, sign_responses, lifetime_seconds
			FROM core.saml_providers WHERE entity_id = $1`, entity).Scan(&assertions, &responses, &lifetime); err != nil {
			t.Fatal(err)
		}
		return
	}
	signing := func(args ...string) error {
		return run(append([]string{"saml", "signing", "-dsn", dsn, "-entity-id", entity}, args...))
	}

	if err := signing("-sign-responses"); err != nil {
		t.Fatal(err)
	}
	if a, r, _ := state(); !a || !r {
		t.Fatalf("after -sign-responses: assertions %v, responses %v, want both", a, r)
	}
	if err := signing("-assertion-lifetime", "600"); err != nil {
		t.Fatal(err)
	}
	if a, r, l := state(); !a || !r || l != 600 {
		t.Errorf("setting only the lifetime left assertions %v, responses %v, lifetime %d; "+
			"want both still signed and 600", a, r, l)
	}
	if err := signing("-sign-assertions=false"); err != nil {
		t.Fatal(err)
	}
	if a, r, _ := state(); a || !r {
		t.Errorf("after -sign-assertions=false: assertions %v, responses %v", a, r)
	}
	if err := signing("-sign-responses=false"); err == nil {
		t.Error("turning off the only signature left was accepted")
	}
	if a, r, _ := state(); a || !r {
		t.Errorf("a refused change was written: assertions %v, responses %v", a, r)
	}
}
