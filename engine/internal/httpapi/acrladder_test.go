package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// The rungs above multi-factor (4.15), at the authorization endpoint and in
// the ID token: "3" needs a passkey or security key, "4" one bound to its
// device. Without one the requirement is refused, not looped; with one the
// form says which sign-in it wants; and the ID token reports the rung a
// request asked for and was given, while one that asked for nothing is told
// what it was told before.
func TestTheUpperRungsNeedAKeyAndAreReported(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET first_party = true WHERE client_id = $1`,
		f.clientID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.webauthn_credentials WHERE user_id = $1::uuid`, f.userID)
	})
	cookie := f.signInAndReturnCookie(t)
	// As a sign-in records them: the methods, and the acr derived from them.
	setAMR := func(amr ...string) {
		t.Helper()
		if _, err := f.pool.Exec(ctx, `UPDATE core.sessions SET amr = $2, acr = $3 WHERE cookie_hash = $1`,
			store.HashToken(cookie), amr, oauth.ACRFromAMR(amr)); err != nil {
			t.Fatal(err)
		}
	}
	addKey := func(deviceBound bool) {
		t.Helper()
		id := make([]byte, 32)
		_, _ = rand.Read(id)
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := store.SaveCredential(ctx, tx, f.userID, f.orgID, "localhost", id, []byte{1}, make([]byte, 16), 0,
			true, !deviceBound, false, []string{"usb"}, "none", "key"); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	authorize := func(extra string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+f.plainAuthz()+extra, nil)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		rec := httptest.NewRecorder()
		f.srv.handleAuthorize(rec, req)
		return rec
	}
	unmet := func(rec *httptest.ResponseRecorder) bool {
		return strings.Contains(rec.Header().Get("Location"), "error=unmet_authentication_requirements")
	}
	// The sign-in form, with the reason; renderLogin answers a page with a
	// message 401.
	asked := func(rec *httptest.ResponseRecorder) bool {
		return rec.Header().Get("Location") == "" && strings.Contains(rec.Body.String(), `name="password"`) &&
			strings.Contains(rec.Body.String(), "passkey or security key")
	}
	coded := func(rec *httptest.ResponseRecorder) string {
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if rec.Code != http.StatusSeeOther || loc == nil {
			return ""
		}
		return loc.Query().Get("code")
	}

	setAMR("pwd", "otp", "mfa")
	setClientFloor(t, f.pool, f.clientID, "3")
	if rec := authorize(""); !unmet(rec) {
		t.Fatalf("a floor of 3 for an account with no key: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	addKey(false)
	if rec := authorize(""); !asked(rec) {
		t.Fatalf("a floor of 3 with a synced passkey held, after an app: %d", rec.Code)
	}
	setAMR("user", "swk", "mfa")
	if rec := authorize(""); coded(rec) == "" {
		t.Fatalf("a synced passkey that verified did not meet 3: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	setClientFloor(t, f.pool, f.clientID, "4")
	if rec := authorize(""); !unmet(rec) {
		t.Fatalf("a floor of 4 with only a synced passkey: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	addKey(true)
	if rec := authorize(""); !asked(rec) {
		t.Fatalf("a floor of 4 with a device-bound key held, after a synced passkey: %d", rec.Code)
	}
	setAMR("user", "hwk", "mfa")
	if rec := authorize(""); coded(rec) == "" {
		t.Fatalf("a device-bound key that verified did not meet 4: %d", rec.Code)
	}

	setClientFloor(t, f.pool, f.clientID, "1")
	idTokenACR := func(code string) string {
		t.Helper()
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {f.clientID},
			"redirect_uri": {"https://rp.test/cb"}, "code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var body struct {
			IDToken string `json:"id_token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.IDToken == "" {
			t.Fatalf("redemption answered %d: %s", rec.Code, rec.Body)
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.Split(body.IDToken, ".")[1])
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			ACR string `json:"acr"`
		}
		_ = json.Unmarshal(raw, &claims)
		return claims.ACR
	}
	if acr := idTokenACR(coded(authorize("&acr_values=4"))); acr != "4" {
		t.Errorf("a request for 4, met, was told acr %q", acr)
	}
	if acr := idTokenACR(coded(authorize(""))); acr != "2" {
		t.Errorf("a request that asked for nothing was told acr %q, want the 2 it was told before", acr)
	}
}
