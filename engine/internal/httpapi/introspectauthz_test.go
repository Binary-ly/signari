package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAPublicClientCannotIntrospect(t *testing.T) {
	f := newTokenFixture(t)
	const verifier = "verifier-for-the-public-introspection-probe-01234"
	code := f.issueCode(t, verifier)
	status, body := f.post(t, f.redeem(code, verifier))
	if status != http.StatusOK {
		t.Fatalf("redemption: %d %v", status, body)
	}
	access, _ := body["access_token"].(string)
	if access == "" {
		t.Fatalf("no access token, so this test could not detect the leak: %v", body)
	}

	// The fixture client is public: client_id only, no secret of any kind.
	form := url.Values{"token": {access}, "client_id": {f.clientID}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	var b map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &b)

	if rec.Code == http.StatusOK {
		t.Fatalf("a public client introspected with no authentication at all "+
			"(status %d, active=%v); §2.1 requires authorization for this endpoint",
			rec.Code, b["active"])
	}
	if b["error"] != "invalid_client" {
		t.Errorf("refused with error=%v, want invalid_client", b["error"])
	}
	// Nothing about the token may leak on the way out.
	for _, leaked := range []string{"active", "sub", "sid", "scope", "aud", "jti"} {
		if _, present := b[leaked]; present {
			t.Errorf("the refusal disclosed %q, which is the disclosure the "+
				"refusal exists to prevent", leaked)
		}
	}
}

// The other half, and the reason the two endpoints differ on purpose.
//
// RFC 7009 §2.1 anticipates a public client revoking a token it holds, and
// revoking your own token discloses nothing. Refusing public clients at
// /introspect must not take /revoke with it — a public SPA signing a user out is
// the ordinary case, and breaking it to fix introspection would trade a small
// disclosure for a real logout failure.
func TestAPublicClientMayStillRevokeItsOwnToken(t *testing.T) {
	f := newTokenFixture(t)
	const verifier = "verifier-for-the-public-revocation-journey-01234"
	code := f.issueCode(t, verifier)
	status, body := f.post(t, f.redeem(code, verifier))
	if status != http.StatusOK {
		t.Fatalf("redemption: %d %v", status, body)
	}
	refresh, _ := body["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh token to revoke: %v", body)
	}

	form := url.Values{"token": {refresh}, "client_id": {f.clientID}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("a public client could not revoke its own refresh token (%d); "+
			"RFC 7009 §2.1 expects exactly this caller", rec.Code)
	}

	// And it actually worked, rather than returning the 200 that §2.2 also uses
	// for tokens it did nothing about.
	status, body = f.post(t, url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {refresh}, "client_id": {f.clientID}})
	if status == http.StatusOK {
		t.Fatal("the refresh token still worked after a 200 from /revoke, so the " +
			"public-client revocation path returns success without revoking")
	}
}
