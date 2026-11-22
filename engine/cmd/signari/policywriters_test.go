package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
)

// The policy settings the engine read and nothing could set (2.30): whether
// dynamic registration may mint a confidential client, and who an attester is.
// Called inside a rolled-back transaction, as credentialdefine_test.go explains.
func TestThePolicySettingsHaveWriters(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.Exec(ctx, "ROLLBACK") }()

	var org string
	if err := conn.QueryRow(ctx, `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&org); err != nil {
		t.Skipf("no organisation: %v", err)
	}
	confidential := func() bool {
		t.Helper()
		var v bool
		if err := conn.QueryRow(ctx, `SELECT allow_confidential FROM core.registration_policies
			WHERE org_id = $1::uuid`, org).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if err := registrationEnable(ctx, conn, org, false, 10, "", true); err != nil {
		t.Fatal(err)
	}
	if !confidential() {
		t.Fatal("-allow-confidential did not allow confidential registration")
	}
	if err := registrationEnable(ctx, conn, org, false, 10, "", false); err != nil {
		t.Fatal(err)
	}
	if confidential() {
		t.Error("registration enable without -allow-confidential left it allowed")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &priv.PublicKey, KeyID: "a1", Algorithm: "ES256", Use: "sig"}}})
	path := filepath.Join(t.TempDir(), "attester.json")
	if err := os.WriteFile(path, jwks, 0o600); err != nil {
		t.Fatal(err)
	}
	description := func() string {
		t.Helper()
		var d *string
		if err := conn.QueryRow(ctx, `SELECT description FROM core.client_attesters
			WHERE org_id = $1::uuid AND name = 'policy-writers'`, org).Scan(&d); err != nil {
			t.Fatal(err)
		}
		if d == nil {
			return ""
		}
		return *d
	}
	if err := attesterAdd(ctx, conn, org, "policy-writers", path, "the platform's device attestation service"); err != nil {
		t.Fatal(err)
	}
	if got := description(); got != "the platform's device attestation service" {
		t.Fatalf("attester add -describe wrote %q", got)
	}
	if err := attesterAdd(ctx, conn, org, "policy-writers", path, ""); err != nil {
		t.Fatal(err)
	}
	if got := description(); got == "" {
		t.Error("re-registering the attester without -describe dropped its description")
	}
}

// federation enable refuses what the Entity Configuration cannot carry, before
// it touches the database (2.30): a trust anchor hint that is not an Entity
// Identifier, and a lifetime outside what the schema allows.
func TestFederationEnableRefusesWhatItCannotPublish(t *testing.T) {
	ctx := context.Background()
	bad := "not an entity id"
	for _, tc := range []struct {
		name     string
		anchors  *string
		lifetime time.Duration
	}{
		{"anchor", &bad, 0},
		{"short lifetime", nil, time.Minute},
		{"long lifetime", nil, 8 * 24 * time.Hour},
	} {
		var life *time.Duration
		if tc.lifetime != 0 {
			life = &tc.lifetime
		}
		// A nil connection: anything that reached the database would panic.
		err := federationEnable(ctx, nil, "https://anchor.example", "", "", tc.anchors, nil, life)
		if err == nil || !(strings.Contains(err.Error(), "trust anchor") || strings.Contains(err.Error(), "-entity-lifetime")) {
			t.Errorf("%s: federation enable answered %v", tc.name, err)
		}
	}
}
