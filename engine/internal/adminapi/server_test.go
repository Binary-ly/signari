package adminapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
)

const testToken = "0123456789abcdef0123456789abcdef" // 32 chars

func newTestServer(t *testing.T) (*Server, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(context.Background(), "SET ROLE signari_maintenance"); err != nil {
		t.Fatalf("role: %v", err)
	}
	s, err := New(pool, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), testToken)
	if err != nil {
		t.Fatal(err)
	}

	// A root key, so the user-attribute routes are registered.
	//
	// Without one they are absent and every request to them is a 404 — which the
	// route-drift test reports as "the route did not succeed, so this test
	// proves nothing", correctly. A fixed key rather than a random one: these
	// tests seal and unseal within a single run, and a per-test key would make a
	// value written by one test unreadable to another that shares a fixture.
	secret := make([]byte, 32)
	secret[0] = 0x5a
	root, err := keys.NewRootKey("test", secret)
	if err != nil {
		t.Fatal(err)
	}
	s.SetRootKey(root)

	return s, pool
}

// A short shared secret cannot be made safe by rate limiting, so it is refused
// where the mistake is cheapest to correct: at construction.
func TestShortTokenRefused(t *testing.T) {
	if _, err := New(nil, slog.Default(), "tooshort"); err == nil {
		t.Fatal("an 8-character admin token was accepted")
	}
	if _, err := New(nil, slog.Default(), strings.Repeat("x", 32)); err != nil {
		t.Fatalf("a 32-character token was refused: %v", err)
	}
}

func TestAuthRequired(t *testing.T) {
	s, _ := newTestServer(t)
	for _, h := range []string{"", "Bearer wrong", "Basic " + testToken, testToken} {
		req := httptest.NewRequest(http.MethodGet, "/admin/config-version", nil)
		if h != "" {
			req.Header.Set("Authorization", h)
		}
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Authorization=%q gave %d, want 401", h, rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("Authorization=%q: 401 without a challenge header", h)
		}
	}
}

// The invariant. A mutation that does not move config_version is durable but
// invisible: every engine node keeps serving the old value with no signal.
func TestMutationBumpsConfigVersion(t *testing.T) {
	s, pool := newTestServer(t)
	ctx := context.Background()

	// Fixture: an instance, org and client to toggle.
	var orgID string
	if err := pool.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://admin-api-test-' || gen_random_uuid() || '.test', 'T')
			RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'o' || substr(gen_random_uuid()::text, 1, 8), 'Org' FROM i
		RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatalf("fixture org: %v", err)
	}
	clientID := "admin-api-" + orgID[:8]
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash)
		VALUES ($1, $2, 'T', 'confidential', 'x')`, clientID, orgID); err != nil {
		t.Fatalf("fixture client: %v", err)
	}

	before := configVersionOf(t, pool)

	rec := doPatch(t, s, clientID, `{"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH gave %d: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Enabled       bool  `json:"enabled"`
		ConfigVersion int64 `json:"config_version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Enabled {
		t.Error("response says enabled=true after disabling")
	}

	after := configVersionOf(t, pool)
	if after <= before {
		t.Fatalf("config_version did not advance: %d -> %d", before, after)
	}
	if body.ConfigVersion != after {
		t.Errorf("response version %d != database version %d", body.ConfigVersion, after)
	}

	// And the write actually landed.
	var enabled bool
	if err := pool.QueryRow(ctx,
		`SELECT enabled FROM core.clients WHERE client_id = $1`, clientID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Error("client is still enabled in the database")
	}
}

// A failed mutation must not advance the version either -- the bump shares the
// transaction, so a rollback takes it along.
func TestFailedMutationDoesNotBumpVersion(t *testing.T) {
	s, pool := newTestServer(t)
	before := configVersionOf(t, pool)

	rec := doPatch(t, s, "no-such-client-"+strings.Repeat("z", 6), `{"enabled":false}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown client gave %d, want 404", rec.Code)
	}
	if after := configVersionOf(t, pool); after != before {
		t.Fatalf("version moved on a failed mutation: %d -> %d", before, after)
	}
}

// Absent and false must be distinguishable, or a PATCH that does not mention
// `enabled` silently disables the client.
func TestAbsentFieldIsNotFalse(t *testing.T) {
	s, pool := newTestServer(t)
	before := configVersionOf(t, pool)

	rec := doPatch(t, s, "irrelevant", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty patch gave %d, want 400", rec.Code)
	}
	if after := configVersionOf(t, pool); after != before {
		t.Fatalf("version moved on a no-op patch: %d -> %d", before, after)
	}
}

func doPatch(t *testing.T, s *Server, clientID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPatch, "/admin/clients/"+clientID, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	return rec
}

func configVersionOf(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var v int64
	if err := pool.QueryRow(context.Background(),
		`SELECT version FROM core.config_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}
