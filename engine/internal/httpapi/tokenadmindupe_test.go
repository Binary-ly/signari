package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestRevokeAndIntrospectRefuseDuplicateParameters pins RFC 6749 3.1 at the
// TokenRevocationEndpoint.checkParameterDuplicated against our two
// token-endpoint-family handlers.
//
// RFC 6749 §3.1 forbids a parameter appearing twice. The authorize, token and
// PAR endpoints refuse it; revoke and introspect flow through the shared
// authenticateTokenEndpointClient, which took the first value via Get() and so
// accepted `token=A&token=B` silently -- answering about A while a proxy or
// audit shipper reading B records a different token. The gap was closed at
// revoke; we did not until this was found by reading their endpoint beside ours.
func TestRevokeAndIntrospectRefuseDuplicateParameters(t *testing.T) {
	f := newTokenFixture(t)
	secret := revocableClient(t, f)

	// A raw form body with `token` twice. url.Values.Encode sorts and emits both,
	// which is exactly the shape a hostile or buggy client sends.
	body := "token=first-token-value&token=second-token-value"

	call := func(t *testing.T, path string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(f.clientID, secret)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var b map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &b)
		return rec.Code, b
	}

	for _, path := range []string{"/oauth2/revoke", "/oauth2/introspect"} {
		t.Run(path, func(t *testing.T) {
			status, b := call(t, path)
			if status != http.StatusBadRequest {
				t.Fatalf("%s with a duplicated token parameter got %d, want 400: a "+
					"duplicate must be refused, not silently resolved to the first value",
					path, status)
			}
			if b["error"] != "invalid_request" {
				t.Errorf("%s error = %v, want invalid_request", path, b["error"])
			}
		})
	}

	// The single-value form still works, so the guard did not break the endpoints.
	t.Run("a single token parameter is still accepted", func(t *testing.T) {
		form := url.Values{"token": {"a-token-that-matches-nothing"}}
		req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(f.clientID, secret)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		// RFC 7009 §2.2: an unknown token is 200, not an error.
		if rec.Code != http.StatusOK {
			t.Fatalf("a single unknown token got %d, want 200 (RFC 7009 §2.2)", rec.Code)
		}
	})
}
