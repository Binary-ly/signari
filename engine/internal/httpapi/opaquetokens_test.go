package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// A client set to opaque, through the life of a token (9.16): what it gets tells whoever
// holds it nothing, every path that takes a token takes this one, revoking it ends it, and
// a read of the table gives nobody a working token. A client left alone is untouched.
func TestAnOpaqueAccessTokenThroughItsLife(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	secret := revocableClient(t, f)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.opaque_access_tokens WHERE client_id = $1`, f.clientID)
	})
	setFormat := func(format string) {
		t.Helper()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := store.SetClientSettings(ctx, tx, f.clientID, store.ClientSettings{AccessTokenFormat: &format}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	redeem := func() map[string]any {
		t.Helper()
		verifier := strings.Repeat("a", 48)
		form := f.redeem(f.issueCodeWithScopes(t, verifier, []string{"openid"}), verifier)
		form.Set("client_secret", secret)
		status, body := f.post(t, form)
		if status != http.StatusOK {
			t.Fatalf("redeeming a code: %d %v", status, body)
		}
		return body
	}
	userinfo := func(token string) int {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, oidc.PathUserinfo, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		return rec.Code
	}
	introspect := func(token string) map[string]any {
		t.Helper()
		form := url.Values{"token": {token}, "client_id": {f.clientID}, "client_secret": {secret}}
		r := httptest.NewRequest(http.MethodPost, oidc.PathIntrospection, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("introspection: %d %s", rec.Code, rec.Body)
		}
		return out
	}

	// Left alone, a client's tokens are what they were.
	jwt := redeem()["access_token"].(string)
	if strings.Count(jwt, ".") != 2 {
		t.Fatalf("a default client got %.40s", jwt)
	}

	setFormat("opaque")
	body := redeem()
	handle := body["access_token"].(string)
	if !strings.HasPrefix(handle, store.OpaqueTokenPrefix) || strings.Contains(handle, ".") {
		t.Fatalf("an opaque client got %.40s", handle)
	}
	if userinfo(jwt) != http.StatusOK {
		t.Error("a JWT issued before the switch stopped working")
	}
	if got := userinfo(handle); got != http.StatusOK {
		t.Errorf("userinfo with a handle: %d", got)
	}
	got := introspect(handle)
	if got["active"] != true || got["sub"] != f.userID || got["client_id"] != f.clientID {
		t.Errorf("introspecting a handle: %v", got)
	}

	// Nothing in the row works, and the handle is not in it.
	var hash, sealed []byte
	if err := f.pool.QueryRow(ctx, `SELECT token_hash, sealed FROM core.opaque_access_tokens WHERE client_id = $1
		ORDER BY expires_at DESC LIMIT 1`, f.clientID).Scan(&hash, &sealed); err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256([]byte(handle)); string(hash) != string(sum[:]) {
		t.Error("the row is not keyed by the handle's hash")
	}
	if strings.Contains(string(sealed), "eyJ") || strings.Contains(string(sealed), handle) {
		t.Error("the row holds a token in the clear")
	}
	wrong := store.OpaqueTokenPrefix + strings.Repeat("A", 43)
	if _, err := store.OpenOpaqueToken(ctx, f.pool, wrong); err == nil {
		t.Error("a handle nobody issued opened something")
	}
	if userinfo(wrong) == http.StatusOK {
		t.Error("userinfo took a handle nobody issued")
	}
	if introspect(wrong)["active"] != false {
		t.Error("introspection called a handle nobody issued active")
	}

	// Revoked by the handle, as the client knows it.
	form := url.Values{"token": {handle}, "client_id": {f.clientID}, "client_secret": {secret}}
	r := httptest.NewRequest(http.MethodPost, oidc.PathRevocation, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoking: %d %s", rec.Code, rec.Body)
	}
	if introspect(handle)["active"] != false {
		t.Error("a revoked handle is still active")
	}
	if userinfo(handle) == http.StatusOK {
		t.Error("userinfo took a revoked handle")
	}

	// Past its expiry it opens nothing, and the janitor takes the row.
	handle = redeem()["access_token"].(string)
	sum := sha256.Sum256([]byte(handle))
	if _, err := f.pool.Exec(ctx, `UPDATE core.opaque_access_tokens SET expires_at = now() - interval '1 minute'
		WHERE token_hash = $1`, sum[:]); err != nil {
		t.Fatal(err)
	}
	if userinfo(handle) == http.StatusOK {
		t.Error("userinfo took an expired handle")
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if n, err := store.PurgeExpiredOpaqueTokens(ctx, tx); err != nil || n == 0 {
		t.Errorf("the sweep: %d, %v", n, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
