package adminapi

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mintToken creates a real token row and returns the secret.
func mintToken(t *testing.T, s *Server, name, orgID string, scopes []string,
	expires *time.Time) string {
	t.Helper()
	secret, _, err := NewToken(context.Background(), s.db, name, orgID, scopes, expires, nil, nil)
	if err != nil {
		t.Fatalf("minting %q: %v", name, err)
	}
	t.Cleanup(func() {
		sum := sha256Of(secret)
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.admin_tokens WHERE token_hash = $1`, sum)
	})
	return secret
}

func call(t *testing.T, s *Server, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = httptest.NewRequest(method, path, strings.NewReader(string(b)))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, r)
	return rec
}

// TestScopeIsEnforcedPerEndpoint.
//
// A token with users:write must not be able to touch clients. This is the whole
// point of scopes: the console holds one credential, and a leak of it should not
// be a leak of everything.
func TestScopeIsEnforcedPerEndpoint(t *testing.T) {
	s, _ := newTestServer(t)
	usersOnly := mintToken(t, s, "users only", "", []string{ScopeUsersWrite}, nil)

	rec := call(t, s, http.MethodPatch, "/admin/clients/whatever", usersOnly,
		map[string]any{"enabled": false})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a users:write token reached a clients endpoint: %d %s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), ScopeClientsWrite) {
		t.Errorf("the refusal should name the missing scope; got %s", rec.Body.String())
	}

	// And the scope it does hold still works -- a check that refuses everything
	// would pass the test above while being useless.
	rec = call(t, s, http.MethodGet, "/admin/config-version", usersOnly, nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("config:read was not required for config-version: %d", rec.Code)
	}
	readToken := mintToken(t, s, "reader", "", []string{ScopeConfigRead}, nil)
	rec = call(t, s, http.MethodGet, "/admin/config-version", readToken, nil)
	if rec.Code != http.StatusOK {
		t.Errorf("a config:read token was refused config-version: %d %s",
			rec.Code, rec.Body.String())
	}
}

func TestRevokedTokenIsRejected(t *testing.T) {
	s, _ := newTestServer(t)
	tok := mintToken(t, s, "to be revoked", "", []string{ScopeConfigRead}, nil)

	if rec := call(t, s, http.MethodGet, "/admin/config-version", tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("the token did not work before revocation: %d", rec.Code)
	}
	if _, err := s.db.Exec(context.Background(),
		`UPDATE core.admin_tokens SET revoked_at = now() WHERE token_hash = $1`,
		sha256Of(tok)); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, s, http.MethodGet, "/admin/config-version", tok, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a revoked token still works: %d", rec.Code)
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	s, _ := newTestServer(t)
	past := time.Now().Add(-time.Hour)
	tok := mintToken(t, s, "expired", "", []string{ScopeConfigRead}, &past)

	if rec := call(t, s, http.MethodGet, "/admin/config-version", tok, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an expired token was accepted: %d", rec.Code)
	}
}

// TestUnknownTokenAndRevokedTokenLookIdentical. Distinguishing them tells an
// attacker which guesses were once real credentials.
func TestUnknownTokenAndRevokedTokenLookIdentical(t *testing.T) {
	s, _ := newTestServer(t)
	tok := mintToken(t, s, "revoked", "", []string{ScopeConfigRead}, nil)
	if _, err := s.db.Exec(context.Background(),
		`UPDATE core.admin_tokens SET revoked_at = now() WHERE token_hash = $1`,
		sha256Of(tok)); err != nil {
		t.Fatal(err)
	}

	revoked := call(t, s, http.MethodGet, "/admin/config-version", tok, nil)
	unknown := call(t, s, http.MethodGet, "/admin/config-version",
		TokenPrefix+"completelymadeupvaluethatneverexisted", nil)

	if revoked.Code != unknown.Code || revoked.Body.String() != unknown.Body.String() {
		t.Errorf("revoked and unknown tokens are distinguishable:\n  revoked: %d %s\n  unknown: %d %s",
			revoked.Code, revoked.Body.String(), unknown.Code, unknown.Body.String())
	}
}

// TestScopeAllCannotBeStored. A saved credential that can do everything is what
// this whole mechanism exists to replace.
func TestScopeAllCannotBeStored(t *testing.T) {
	s, _ := newTestServer(t)
	_, _, err := NewToken(context.Background(), s.db, "god mode", "", []string{ScopeAll}, nil, nil, nil)
	if err == nil {
		t.Fatal("a token carrying * was created")
	}
	if !strings.Contains(err.Error(), "break-glass") {
		t.Errorf("the error should point at the break-glass token; got %v", err)
	}
}

func TestUnknownScopeIsRefused(t *testing.T) {
	s, _ := newTestServer(t)
	if _, _, err := NewToken(context.Background(), s.db, "typo", "",
		[]string{"users:wrote"}, nil, nil, nil); err == nil {
		t.Fatal("a misspelled scope was accepted; it would grant nothing and look granted")
	}
}

func TestNamelessTokenIsRefused(t *testing.T) {
	s, _ := newTestServer(t)
	if _, _, err := NewToken(context.Background(), s.db, "  ", "",
		[]string{ScopeConfigRead}, nil, nil, nil); err == nil {
		t.Fatal("a token with no name was created")
	}
}

// TestBreakGlassTokenStillWorks. It is the path that has to work when the
// database does not, so it must not have been broken by adding stored tokens.
func TestBreakGlassTokenStillWorks(t *testing.T) {
	s, _ := newTestServer(t)
	if rec := call(t, s, http.MethodGet, "/admin/config-version", testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("the environment token was refused: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPrincipalScopeMatching(t *testing.T) {
	p := &Principal{Scopes: []string{ScopeUsersWrite}}
	if !p.Can(ScopeUsersWrite) {
		t.Error("a held scope was not matched")
	}
	if p.Can(ScopeClientsWrite) {
		t.Error("an unheld scope was matched")
	}
	all := &Principal{Scopes: []string{ScopeAll}}
	for _, sc := range KnownScopes {
		if !all.Can(sc) {
			t.Errorf("* did not cover %s", sc)
		}
	}
}

func TestMayActOn(t *testing.T) {
	const orgA = "11111111-1111-1111-1111-111111111111"
	const orgB = "22222222-2222-2222-2222-222222222222"

	unscoped := &Principal{}
	if err := unscoped.MayActOn(orgA); err != nil {
		t.Errorf("an unscoped token was refused an organisation: %v", err)
	}
	if err := unscoped.MayActOn(""); err != nil {
		t.Errorf("an unscoped token was refused an empty organisation: %v", err)
	}

	scoped := &Principal{OrgID: orgA}
	if err := scoped.MayActOn(orgA); err != nil {
		t.Errorf("a scoped token was refused its own organisation: %v", err)
	}
	if err := scoped.MayActOn(orgB); err == nil {
		t.Error("a scoped token reached another organisation")
	}
	// An empty target must be refused, not treated as "no restriction applies".
	// That inversion is how a boundary check becomes a no-op.
	if err := scoped.MayActOn(""); err == nil {
		t.Error("a scoped token was allowed to act with no organisation named")
	}
}

// TestNoPrincipalFailsClosed. If a handler is ever registered without auth(),
// the boundary check must refuse rather than treat "nobody" as "unrestricted".
func TestNoPrincipalFailsClosed(t *testing.T) {
	if err := requireOrg(context.Background(), "some-org"); err == nil {
		t.Fatal("requireOrg permitted a request with no principal on the context")
	}
}

// makeOrg creates a throwaway organisation.
func makeOrg(t *testing.T, s *Server, name string) string {
	t.Helper()
	var id string
	if err := s.db.QueryRow(context.Background(),
		`INSERT INTO core.organizations (instance_id, slug, display_name)
		 SELECT id, $1, $1 FROM core.instances ORDER BY created_at LIMIT 1
		 RETURNING id::text`, name).Scan(&id); err != nil {
		// Fatal, NOT Skip. A skipped boundary test reads exactly like a passing
		// one in the summary, and this is the check the whole change exists for.
		t.Fatalf("cannot create an organisation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.organizations WHERE id = $1::uuid`, id)
	})
	return id
}

// TestOrganisationBoundaryHoldsThroughTheHandlers is the test this whole change
// exists for.
//
// A token scoped to one tenant must not reach another, and it must hold at BOTH
// places an organisation is decided: the request body on a create, and the
// existing row on an update. A boundary that holds for creates and not for edits
// is worse than none, because it reads as enforced.
func TestOrganisationBoundaryHoldsThroughTheHandlers(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()

	orgA := makeOrg(t, s, "boundary-a-"+randSuffix(t))
	orgB := makeOrg(t, s, "boundary-b-"+randSuffix(t))

	// A token that may only touch org A.
	tok := mintToken(t, s, "org A console", orgA,
		[]string{ScopeUsersWrite, ScopeClientsWrite}, nil)

	t.Run("create in its own org is allowed", func(t *testing.T) {
		rec := call(t, s, http.MethodPost, "/admin/users", tok, map[string]any{
			"org_id": orgA, "email": "inside-" + randSuffix(t) + "@example.test",
		})
		if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
			t.Fatalf("refused a create in its own organisation: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("create in another org is refused", func(t *testing.T) {
		rec := call(t, s, http.MethodPost, "/admin/users", tok, map[string]any{
			"org_id": orgB, "email": "outside-" + randSuffix(t) + "@example.test",
		})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("a token scoped to org A created a user in org B: %d %s",
				rec.Code, rec.Body.String())
		}
	})

	t.Run("editing another org's user is refused", func(t *testing.T) {
		// A user that belongs to B, created directly so the API is not the thing
		// under test twice.
		handle := make([]byte, 64)
		if _, err := cryptorand.Read(handle); err != nil {
			t.Fatal(err)
		}
		var victimID string
		if err := s.db.QueryRow(ctx,
			`INSERT INTO core.users (org_id, email, user_handle, status)
			 VALUES ($1::uuid, $2, $3, 'active') RETURNING id::text`,
			orgB, "victim-"+randSuffix(t)+"@example.test", handle).Scan(&victimID); err != nil {
			t.Fatalf("cannot seed a user: %v", err)
		}
		defer func() { _, _ = s.db.Exec(ctx, `DELETE FROM core.users WHERE id=$1::uuid`, victimID) }()

		rec := call(t, s, http.MethodPatch, "/admin/users/"+victimID, tok,
			map[string]any{"active": false})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("a token scoped to org A deactivated a user in org B: %d %s",
				rec.Code, rec.Body.String())
		}
	})

	t.Run("editing another org's client is refused", func(t *testing.T) {
		clientID := "victim-client-" + randSuffix(t)
		if _, err := s.db.Exec(ctx,
			`INSERT INTO core.clients (client_id, org_id, display_name, client_type, enabled)
			 VALUES ($1, $2::uuid, $1, 'public', true)`, clientID, orgB); err != nil {
			t.Fatalf("cannot seed a client: %v", err)
		}
		defer func() { _, _ = s.db.Exec(ctx, `DELETE FROM core.clients WHERE client_id=$1`, clientID) }()

		rec := call(t, s, http.MethodPatch, "/admin/clients/"+clientID, tok,
			map[string]any{"enabled": false})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("a token scoped to org A disabled a client in org B: %d %s",
				rec.Code, rec.Body.String())
		}

		// And it really is still enabled -- a 403 that rolled back nothing would
		// pass the check above while the damage was already committed.
		var enabled bool
		if err := s.db.QueryRow(ctx,
			`SELECT enabled FROM core.clients WHERE client_id = $1`, clientID).Scan(&enabled); err != nil {
			t.Fatal(err)
		}
		if !enabled {
			t.Error("the client was disabled despite the request being refused")
		}
	})

	t.Run("an unscoped token still reaches both", func(t *testing.T) {
		global := mintToken(t, s, "global console", "", []string{ScopeUsersWrite}, nil)
		for _, org := range []string{orgA, orgB} {
			rec := call(t, s, http.MethodPost, "/admin/users", global, map[string]any{
				"org_id": org, "email": "global-" + randSuffix(t) + "@example.test",
			})
			if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
				t.Errorf("an unscoped token was refused org %s: %d %s",
					org, rec.Code, rec.Body.String())
			}
		}
	})
}

func randSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := cryptorand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
