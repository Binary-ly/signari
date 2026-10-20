package main

import (
	"context"
	"fmt"
	"os"
	"strings"
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

// `saml signing -signature-alg` sets what a provider is signed with, and
// refuses an algorithm the provider's own instance has no active key for,
// which would fail every one of its sign-ins at signing (3.15). A flag not
// given leaves the algorithm alone.
//
// A fresh instance with no keys, removed afterwards.
func TestSAMLSigningSetsTheSignatureAlgorithm(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) }) // after the deletes below
	var org, instance, entity string
	if err := db.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name)
		           VALUES ('https://saml-cli-' || gen_random_uuid() || '.test', 'SAML CLI test') RETURNING id),
		     o AS (INSERT INTO core.organizations (instance_id, slug, display_name)
		           SELECT id, 's' || substr(gen_random_uuid()::text, 1, 8), 'SAML' FROM i
		           RETURNING id, instance_id)
		INSERT INTO core.saml_providers (org_id, entity_id, display_name)
		SELECT id, 'urn:test:samlcli:' || gen_random_uuid(), 'SP' FROM o
		RETURNING org_id::text, (SELECT instance_id::text FROM o), entity_id`).Scan(&org, &instance, &entity); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = db.Exec(c, `DELETE FROM core.signing_keys WHERE instance_id = $1::uuid`, instance)
		_, _ = db.Exec(c, `DELETE FROM core.organizations WHERE id = $1::uuid`, org)
		_, _ = db.Exec(c, `DELETE FROM core.instances WHERE id = $1::uuid`, instance)
	})
	signing := func(flags ...string) error {
		return run(append([]string{"saml", "signing", "-dsn", dsn, "-entity-id", entity}, flags...))
	}
	alg := func() string {
		t.Helper()
		var a string
		if err := db.QueryRow(ctx, `SELECT signature_alg FROM core.saml_providers WHERE entity_id = $1`,
			entity).Scan(&a); err != nil {
			t.Fatal(err)
		}
		return a
	}

	if alg() != "rsa-sha256" {
		t.Fatalf("a new provider is signed with %s, want rsa-sha256", alg())
	}
	if err := signing("-signature-alg", "ecdsa-sha256"); err == nil || !strings.Contains(err.Error(), "keys rotate -alg ES256") {
		t.Errorf("ecdsa-sha256 with no active ES256 key in the provider's instance: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO core.signing_keys (kid, instance_id, algorithm, state, public_jwk, key_ref)
		VALUES ('samlcli-' || gen_random_uuid(), $1::uuid, 'ES256', 'active', '{}', 'test:in-memory')`,
		instance); err != nil {
		t.Fatal(err)
	}
	if err := signing("-signature-alg", "ecdsa-sha256"); err != nil {
		t.Fatalf("ecdsa-sha256 with an active ES256 key: %v", err)
	}
	if alg() != "ecdsa-sha256" {
		t.Fatalf("after -signature-alg ecdsa-sha256 the provider is signed with %s", alg())
	}
	if err := signing("-sign-responses"); err != nil {
		t.Fatal(err)
	}
	if alg() != "ecdsa-sha256" {
		t.Errorf("a change to what is signed reset the algorithm to %s", alg())
	}
	if err := signing("-signature-alg", "rsa-sha512"); err == nil || !strings.Contains(err.Error(), "rsa-sha256 or ecdsa-sha256") {
		t.Errorf("an algorithm with no meaning here: %v", err)
	}
	if err := run([]string{"saml", "signing", "-dsn", dsn, "-entity-id", entity + "-missing",
		"-signature-alg", "ecdsa-sha256"}); err == nil || !strings.Contains(err.Error(), "no SAML service provider") {
		t.Errorf("an unknown provider: %v", err)
	}
}
