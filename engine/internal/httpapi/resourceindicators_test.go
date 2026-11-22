package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// A requested resource becomes the access token's audience, so it must be a
// resource server the client's organisation registered (1.87). The shape was
// the only check, and the comment over it said that stopped a client widening
// a token: any client could name any https URI and be issued a token another
// organisation's API, or an internal service trusting this issuer, accepted.
// The device endpoint checked not even the shape.
func TestAResourceTheOrganisationDidNotRegisterIsRefused(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	registered := "https://api.registered.example.test/" + strings.ReplaceAll(t.Name(), "/", "-")
	unregistered := "https://api.nobody.example.test/v1"
	f.registerResource(t, registered)

	// Registered by ANOTHER organisation, which is no registration for this one.
	var other string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, 'rs-' || substr(gen_random_uuid()::text, 1, 8), 'Other'
		  FROM core.organizations WHERE id = $1::uuid RETURNING id::text`, f.orgID).Scan(&other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.organizations WHERE id = $1::uuid`, other)
	})
	theirs := "https://api.theirs.example.test/v1"
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.resource_servers (org_id, resource) VALUES ($1::uuid, $2)`,
		other, theirs); err != nil {
		t.Fatal(err)
	}

	t.Run("authorize", func(t *testing.T) {
		authorize := func(resource string) *httptest.ResponseRecorder {
			q := url.Values{"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
				"response_type": {"code"}, "scope": {"openid"}, "state": {"s"},
				"code_challenge":        {oauth.Challenge("verifier-resource-authorize-0123456789abcdef")},
				"code_challenge_method": {"S256"}, "resource": {resource}}
			rec := httptest.NewRecorder()
			f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil))
			return rec
		}
		for name, resource := range map[string]string{"unregistered": unregistered, "another organisation's": theirs} {
			rec := authorize(resource)
			loc := rec.Header().Get("Location")
			if !strings.HasPrefix(loc, "https://rp.test/cb") || !strings.Contains(loc, "error=invalid_target") {
				t.Errorf("an %s resource answered %d %q, want a redirect to the client with invalid_target",
					name, rec.Code, loc)
			}
		}
		if loc := authorize(registered).Header().Get("Location"); strings.Contains(loc, "invalid_target") {
			t.Errorf("a registered resource was refused: %q", loc)
		}
	})

	t.Run("par", func(t *testing.T) {
		push := func(resource string) (int, map[string]any) {
			form := url.Values{"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
				"response_type": {"code"}, "scope": {"openid"},
				"code_challenge":        {oauth.Challenge("verifier-resource-par-0123456789abcdefghij")},
				"code_challenge_method": {"S256"}, "resource": {resource}}
			req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = "198.51.100.87:1234"
			rec := httptest.NewRecorder()
			f.srv.Routes().ServeHTTP(rec, req)
			var body map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			return rec.Code, body
		}
		if code, body := push(unregistered); code != http.StatusBadRequest || body["error"] != "invalid_target" {
			t.Errorf("an unregistered resource pushed: %d %v, want 400 invalid_target", code, body)
		}
		if code, body := push(registered); code != http.StatusCreated {
			t.Errorf("a registered resource pushed: %d %v, want 201", code, body)
		}
	})

	t.Run("device", func(t *testing.T) {
		if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET grant_types = grant_types || $2::text
			WHERE client_id = $1`, f.clientID, oauth.GrantTypeDeviceCode); err != nil {
			t.Fatal(err)
		}
		start := func(resource string) (int, map[string]any) {
			form := url.Values{"client_id": {f.clientID}, "scope": {"openid"}, "resource": {resource}}
			req := httptest.NewRequest(http.MethodPost, "/oauth2/device_authorization", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			f.srv.Routes().ServeHTTP(rec, req)
			var body map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			return rec.Code, body
		}
		for _, resource := range []string{unregistered, "not a uri", theirs} {
			if code, body := start(resource); code != http.StatusBadRequest || body["error"] != "invalid_target" {
				t.Errorf("device authorization for %q: %d %v, want 400 invalid_target", resource, code, body)
			}
		}
		if code, body := start(registered); code != http.StatusOK {
			t.Errorf("device authorization for a registered resource: %d %v, want 200", code, body)
		}
	})

	// The mint checks again, so a resource removed after a code or a refresh
	// token was issued for it stops new tokens -- and a refused refresh spends
	// nothing, so it works again once the resource is back.
	t.Run("minted after removal", func(t *testing.T) {
		resource := "https://api.removed.example.test/" + time.Now().Format("150405.000000")
		f.registerResource(t, resource)
		verifier := "verifier-resource-removed-0123456789abcdefgh"
		code := f.issueCodeForResourceWithScopes(t, verifier, resource, "openid", "offline_access")
		status, body := f.post(t, f.redeem(code, verifier))
		if status != http.StatusOK {
			t.Fatalf("redeeming a code for a registered resource: %d %v", status, body)
		}
		access, _ := body["access_token"].(string)
		refresh, _ := body["refresh_token"].(string)
		if aud := audienceOf(t, access); len(aud) != 1 || aud[0] != resource {
			t.Fatalf("the access token's audience is %v, want [%s]", aud, resource)
		}
		if refresh == "" {
			t.Fatal("no refresh token issued")
		}
		if _, err := f.pool.Exec(ctx, `DELETE FROM core.resource_servers WHERE org_id = $1::uuid AND resource = $2`,
			f.orgID, resource); err != nil {
			t.Fatal(err)
		}
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {f.clientID}}
		if status, body := f.post(t, form); status != http.StatusBadRequest || body["error"] != "invalid_target" {
			t.Errorf("a refresh for a removed resource: %d %v, want 400 invalid_target", status, body)
		}
		f.registerResource(t, resource)
		if status, body := f.post(t, form); status != http.StatusOK {
			t.Errorf("the same refresh once the resource is back: %d %v, want 200 (the refusal spent it)", status, body)
		}

		other := f.issueCodeForResourceWithScopes(t, verifier, unregistered, "openid")
		if _, err := f.pool.Exec(ctx, `DELETE FROM core.resource_servers WHERE org_id = $1::uuid AND resource = $2`,
			f.orgID, unregistered); err != nil {
			t.Fatal(err)
		}
		if status, body := f.post(t, f.redeem(other, verifier)); status != http.StatusBadRequest ||
			body["error"] != "invalid_target" {
			t.Errorf("a code for an unregistered resource redeemed: %d %v, want 400 invalid_target", status, body)
		}
	})
}

// issueCodeForResourceWithScopes plants a code for resource, as
// issueCodeForResource does, with the scopes given.
func (f *tokenFixture) issueCodeForResourceWithScopes(t *testing.T, verifier, resource string, scopes ...string) string {
	t.Helper()
	ctx := context.Background()
	f.registerResource(t, resource)
	code, hash, err := store.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	grant := oauth.GrantRecord{
		ClientID: f.clientID, RedirectURI: "https://rp.test/cb",
		CodeChallenge: oauth.Challenge(verifier), CodeChallengeMethod: "S256",
		Scopes: scopes, ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := store.IssueCode(ctx, tx, f.orgID, f.clientID, f.sid, f.userID, grant, hash, []string{resource}, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchSessionClient(ctx, tx, f.sid, f.clientID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return code
}

// audienceOf reads a JWT's aud without verifying it; the tests that call it
// verify elsewhere.
func audienceOf(t *testing.T, jwt string) []string {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Aud []string `json:"aud"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims.Aud
}
