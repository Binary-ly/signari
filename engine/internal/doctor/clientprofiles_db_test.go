package doctor

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// A flow branching on what only a provider answers, with no provider, reads false, which
// looks like a guard and guards nothing, so doctor says so until one is registered (10.02).
func TestAFlowAskingAProviderNobodyRegisteredIsReported(t *testing.T) {
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
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var org string
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'flowq-' || substr(gen_random_uuid()::text, 1, 8), 'Q' FROM core.instances LIMIT 1
		RETURNING id::text`).Scan(&org); err != nil {
		t.Skipf("no instance to make an organisation in: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.sign_in_flows (org_id, document) VALUES ($1::uuid, $2)`, org, `
version: 1
flows:
  - name: asks-a-provider
    on: authentication
    stages:
      - password
      - {stage: mfa, when: provider_condition}
      - session
    tests:
      - {name: yes, given: {provider_condition: true}, expect: [password, mfa, session]}
      - {name: no, given: {}, expect: [password, session]}
`); err != nil {
		t.Fatal(err)
	}
	said := func() bool {
		t.Helper()
		r := &Report{}
		if err := checkSignInFlows(ctx, tx.Conn(), r); err != nil {
			t.Fatal(err)
		}
		for _, f := range r.Findings {
			if f.Severity == Warning && strings.Contains(f.Summary, "asks-a-provider") {
				return true
			}
		}
		return false
	}
	if !said() {
		t.Error("doctor said nothing of a flow asking a provider nobody registered")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.providers (org_id, name, hook, url, mode, timeout_ms)
		VALUES ($1::uuid, 'p', 'flow_condition', 'https://p.test/', 'fail_closed', 2000)`, org); err != nil {
		t.Fatal(err)
	}
	if said() {
		t.Error("doctor still complained with a provider registered")
	}
}

// A client that has left the profile it is held to is refused without being told why, so
// doctor is where an operator hears of it (9.05). A client held to nothing is not asked.
func TestAClientOutOfItsSecurityProfileIsReported(t *testing.T) {
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
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	n := time.Now().UnixNano()
	held, free := fmt.Sprintf("held-%d", n), fmt.Sprintf("free-%d", n)
	for id, profile := range map[string]string{held: "fapi2", free: "none"} {
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash, security_profile)
			SELECT $1, id, 'P', 'public', '', $2 FROM core.organizations LIMIT 1`, id, profile); err != nil {
			t.Fatal(err)
		}
	}
	r := &Report{}
	if err := checkClientProfiles(ctx, tx.Conn(), r); err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, f := range r.Findings {
		if f.Severity == Warning && strings.Contains(f.Summary, fmt.Sprint(n)) {
			found = append(found, f.Summary)
		}
	}
	if len(found) != 1 || !strings.Contains(found[0], held) || !strings.Contains(found[0], "confidential") {
		t.Errorf("doctor said %q; want the one client out of its profile, and why", found)
	}
}
