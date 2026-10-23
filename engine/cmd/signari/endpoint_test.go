package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/adminapi"
)

// adminAPIFor is an Admin API over the test database on a loopback server,
// and an organisation of the test's own.
func adminAPIFor(t *testing.T) (url, org string, pool *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	s, err := adminapi.New(pool, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), "")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	slug := fmt.Sprintf("endpoint-%d", time.Now().UnixNano())
	if err := pool.QueryRow(ctx, `INSERT INTO core.organizations (slug, display_name, instance_id)
		VALUES ($1, 'Endpoint test', (SELECT id FROM core.instances ORDER BY created_at LIMIT 1))
		RETURNING id::text`, slug).Scan(&org); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM core.users WHERE org_id = $1::uuid`, org)
		_, _ = pool.Exec(c, `DELETE FROM core.groups WHERE org_id = $1::uuid`, org)
		_, _ = pool.Exec(c, `DELETE FROM core.admin_tokens WHERE org_id = $1::uuid`, org)
		_, _ = pool.Exec(c, `DELETE FROM core.organizations WHERE id = $1::uuid`, org)
	})
	return srv.URL, org, pool
}

// tokenFor mints a stored admin token for the organisation and puts it where
// the CLI reads it.
func tokenFor(t *testing.T, pool *pgxpool.Pool, org string, scopes ...string) (id string) {
	t.Helper()
	secret, id, err := adminapi.NewToken(context.Background(), pool, "endpoint-"+strings.Join(scopes, "-"), org,
		scopes, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNARI_ADMIN_TOKEN", secret)
	return id
}

// A command in endpoint mode makes its change through the Admin API as the
// token it presents (6.16): the API records it under that token's id, and
// refuses it when the token's scopes do not allow it, with no database
// credentials given to the command at all.
func TestAnEndpointModeWriteIsAuditedAndScoped(t *testing.T) {
	url, org, pool := adminAPIFor(t)
	ctx := context.Background()
	t.Setenv("SIGNARI_DSN", "")
	email := fmt.Sprintf("endpoint-%d@example.test", time.Now().UnixNano())

	// A token for groups cannot make a person.
	tokenFor(t, pool, org, "groups:write")
	err := run([]string{"user", "create", "-admin-url", url, "-org", org, "-email", email})
	var refused apiError
	if !errors.As(err, &refused) || refused.Status != 403 || exitCode(err) != 1 {
		t.Fatalf("user create with a groups:write token answered %v (exit %d), want the API's 403", err, exitCode(err))
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM core.users WHERE lower(email) = lower($1)`, email).Scan(&n)
	if n != 0 {
		t.Fatal("the refused user was created")
	}

	// One for users can, and the record names it.
	tokenID := tokenFor(t, pool, org, "users:write")
	if _, err := captureStdout(t, func() error {
		return run([]string{"user", "create", "-admin-url", url, "-org", org, "-email", email})
	}); err != nil {
		t.Fatalf("user create through the Admin API: %v", err)
	}
	var userID, recordedBy string
	if err := pool.QueryRow(ctx, `SELECT id::text FROM core.users WHERE lower(email) = lower($1)`, email).
		Scan(&userID); err != nil {
		t.Fatalf("the user was not created: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT COALESCE(admin_token_id::text, '') FROM core.audit_events
		WHERE event_type = 'admin.user_created' AND subject_id = $1::uuid`, userID).Scan(&recordedBy); err != nil ||
		recordedBy != tokenID {
		t.Errorf("the creation was recorded by %q (%v), want the token %s", recordedBy, err, tokenID)
	}

	// signari api reaches any route as the same token.
	out, err := captureStdout(t, func() error { return run([]string{"api", "GET", "/admin/me", "-admin-url", url}) })
	var me map[string]any
	if err != nil || json.Unmarshal([]byte(out), &me) != nil || !strings.Contains(out, "users:write") {
		t.Errorf("signari api GET /admin/me answered %v:\n%s", err, out)
	}
	if err := run([]string{"api", "POST", "/admin/groups", "-admin-url", url, "-data",
		`{"org_id":"` + org + `","name":"from-api"}`}); exitCode(err) != 1 {
		t.Errorf("a write the token's scopes do not allow answered %v", err)
	}

	// The token comes from a file as well, never from a flag's value.
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(os.Getenv("SIGNARI_ADMIN_TOKEN")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNARI_ADMIN_TOKEN", "")
	if _, err := captureStdout(t, func() error {
		return run([]string{"api", "GET", "/admin/me", "-admin-url", url, "-token-file", file})
	}); err != nil {
		t.Errorf("signari api with -token-file: %v", err)
	}
	if err := run([]string{"api", "GET", "/admin/me", "-admin-url", url}); exitCode(err) != 2 {
		t.Errorf("no token at all answered %v", err)
	}
}

// The bearer token is the credential, so it is sent in the clear only where it
// cannot cross a network, and a request is shaped as the API expects before
// anything is sent.
func TestTheAdminAPIClientRefusesWhatWouldLeakOrCannotWork(t *testing.T) {
	t.Setenv("SIGNARI_ADMIN_TOKEN", "x")
	for _, args := range [][]string{
		{"api", "GET", "/admin/me", "-admin-url", "http://admin.example.test"},
		{"api", "GET", "/admin/me", "-admin-url", "ftp://admin.example.test"},
		{"api", "GET", "/me", "-admin-url", "https://admin.example.test"},
		{"api", "TRACE", "/admin/me", "-admin-url", "https://admin.example.test"},
		{"api", "POST", "/admin/groups", "-admin-url", "https://admin.example.test", "-data", "{not json"},
		{"api", "GET"},
	} {
		if err := run(args); exitCode(err) != 2 {
			t.Errorf("%v answered %v (exit %d), want a usage error before anything is sent", args, err, exitCode(err))
		}
	}
	if _, err := newAPIClient("http://127.0.0.1:1", ""); err != nil {
		t.Errorf("plaintext to loopback was refused: %v", err)
	}
}
