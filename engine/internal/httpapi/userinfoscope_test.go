package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/tokens"
)

// ASVS 5.0 V10.3.2: the resource server enforces `sub`, `scope` and
// `authorization_details` in its decision.
//
// The scope half is a data-disclosure control at `/userinfo`: `email` is
// released only to a token carrying the `email` scope, `profile` only with
// `profile`. The handler does gate each claim — and no test varied the scope,
// so nothing established that a claim is actually WITHHELD.
//
// That is the direction that matters. A test which asks for everything and
// receives everything passes identically against a handler that ignores scope
// altogether; only asking for less and checking that less comes back can tell
// the two apart. What leaks otherwise is a user's address to a client the user
// never released it to, silently.
func TestUserinfoWithholdsClaimsTheScopeDidNotGrant(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	// The user needs an address for its absence to mean anything.
	const addr = "scope-probe@example.test"
	if _, err := f.pool.Exec(ctx,
		`UPDATE core.users SET email = $2, email_verified_at = now() WHERE id = $1::uuid`,
		f.userID, addr); err != nil {
		t.Fatalf("setting an email: %v", err)
	}

	call := func(t *testing.T, scope string) map[string]any {
		t.Helper()
		k, err := f.srv.cfg.Keys.Active(keys.ES256)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		raw, err := tokens.NewSigner(k).SignJSON(tokens.AccessTokenClaims{
			Issuer: f.srv.cfg.Issuer, Subject: f.userID,
			Audience: []string{f.clientID},
			Expiry:   now.Add(time.Minute).Unix(), IssuedAt: now.Unix(),
			JTI: "userinfo-scope-" + strings.ReplaceAll(scope, " ", "-"),
			ClientID: f.clientID, Scope: scope,
		}, tokens.TypAccessToken)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, oidc.PathUserinfo, nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("userinfo with scope %q gave %d: %s", scope, rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding userinfo: %v", err)
		}
		return body
	}

	t.Run("openid alone releases the subject and nothing else", func(t *testing.T) {
		body := call(t, "openid")
		if body["sub"] == nil {
			t.Error("no sub returned; openid must at least identify the user")
		}
		if got, leaked := body["email"]; leaked {
			t.Errorf("email %v was released to a token that never carried the "+
				"`email` scope. The user released their address to nobody here: %v",
				got, body)
		}
		if _, leaked := body["email_verified"]; leaked {
			t.Errorf("email_verified leaked without the email scope: %v", body)
		}
	})

	// The positive case, so the negative cannot pass by the endpoint returning
	// nothing at all.
	t.Run("the email scope releases it", func(t *testing.T) {
		body := call(t, "openid email")
		if body["email"] != addr {
			t.Errorf("email = %v, want %q released when the scope grants it: %v",
				body["email"], addr, body)
		}
	})
}
