package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/oidc"
)

// A stranger's form is read before anything has checked who they are, so each of these
// stops at the cap and not at net/http's ten megabytes.
func TestTheTokenFamilyCapsItsForm(t *testing.T) {
	f := newTokenFixture(t)
	body := "grant_type=client_credentials&padding=" + strings.Repeat("a", maxTokenFormBody+1)
	for _, path := range []string{oidc.PathToken, oidc.PathRevocation, oidc.PathIntrospection,
		"/oauth2/device_authorization", "/oauth2/backchannel"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s read %d bytes and answered %d: %s", path, len(body), rec.Code, rec.Body.String())
		}
	}
	// Under it nothing has changed: this is refused for the client, not the size.
	code, out := f.post(t, url.Values{"grant_type": {"client_credentials"}, "client_id": {"nobody"},
		"padding": {strings.Repeat("a", maxTokenFormBody/2)}})
	if code != http.StatusUnauthorized || out["error"] != "invalid_client" {
		t.Errorf("a form under the cap answered %d %v", code, out)
	}
}

// A hint is an optimisation: wrong, it still finds the token, either way round.
func TestAnIntrospectionHintNeverHidesAToken(t *testing.T) {
	f := newTokenFixture(t)
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(t.Context(), `UPDATE core.clients SET grant_types = ARRAY['client_credentials'],
		client_type = 'confidential', client_secret_hash = $2, scopes = ARRAY['api']
		WHERE client_id = $1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	code, tok := f.post(t, url.Values{"grant_type": {"client_credentials"}, "client_id": {f.clientID},
		"client_secret": {secret}, "scope": {"api"}})
	if code != http.StatusOK {
		t.Fatalf("minting: %d %v", code, tok)
	}
	access, _ := tok["access_token"].(string)
	for _, hint := range []string{"", "access_token", "refresh_token", "something-else"} {
		form := url.Values{"token": {access}, "client_id": {f.clientID}, "client_secret": {secret}}
		if hint != "" {
			form.Set("token_type_hint", hint)
		}
		req := httptest.NewRequest(http.MethodPost, oidc.PathIntrospection, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"active":true`) {
			t.Errorf("hint %q answered %d %s", hint, rec.Code, rec.Body.String())
		}
	}
}
