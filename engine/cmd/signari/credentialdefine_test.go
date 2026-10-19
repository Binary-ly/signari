package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// `credential define -require-key-attestation` sets the requirement, and a
// redefinition that leaves the flag out keeps it (2.07). The upsert rewrote
// every field, so redefining a credential's claims would otherwise drop a
// requirement somebody set, and the metadata would stop advertising it.
//
// Called inside a transaction that is rolled back, not through run(): the
// issuer metadata tests in httpapi need a deployment with no configuration at
// all, and one committed here, in a package running beside them, made them
// fail. The flag reaches credentialDefine as saml signing's do, through a
// pointer that is nil when the flag was not given.
func TestCredentialDefineKeepsTheAttestationRequirementUnlessTold(t *testing.T) {
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
	const config = "AttestedCredential"
	define := func(require *bool) {
		t.Helper()
		if err := credentialDefine(ctx, conn, org, config, "https://cli-test.example/attested",
			"", "email", time.Hour, "", require); err != nil {
			t.Fatalf("credential define: %v", err)
		}
	}
	required := func() bool {
		t.Helper()
		var r bool
		if err := conn.QueryRow(ctx, `SELECT require_key_attestation FROM core.credential_configurations
			WHERE org_id = $1::uuid AND config_id = $2`, org, config).Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	yes, no := true, false

	define(nil)
	if required() {
		t.Fatal("a new configuration requires an attestation without being told to")
	}
	define(&yes)
	if !required() {
		t.Fatal("-require-key-attestation did not set the requirement")
	}
	define(nil)
	if !required() {
		t.Error("redefining without the flag dropped the requirement")
	}
	define(&no)
	if required() {
		t.Error("-require-key-attestation=false did not lift it")
	}
}
