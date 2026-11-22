package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// A client set to require PAR refuses a plain authorization request and
// accepts a pushed one. The column had a reader and no writer, so no client
// could be made to require it (2.23), and nothing tested the refusal.
func TestAPARRequiredClientRefusesAPlainRequest(t *testing.T) {
	f := newTokenFixture(t)
	sum := sha256.Sum256([]byte("verifier-par-required-aaaaaaaaaaaaaaaaaaaaaaaa"))
	params := url.Values{
		"response_type": {"code"}, "client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"scope": {"openid"}, "state": {"s"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	authorize := func(q url.Values) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil))
		return rec
	}
	refused := func(rec *httptest.ResponseRecorder) bool {
		return rec.Code == http.StatusBadRequest && strings.Contains(rec.Body.String(), "pushing the request first")
	}

	if rec := authorize(params); refused(rec) {
		t.Fatal("a plain request was refused before PAR was required")
	}
	on := true
	if err := setClientSettings(t, f, store.ClientSettings{RequirePAR: &on}); err != nil {
		t.Fatal(err)
	}
	if rec := authorize(params); !refused(rec) {
		t.Fatalf("a PAR-required client's plain request answered %d", rec.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	var pushed struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pushed); err != nil || pushed.RequestURI == "" {
		t.Fatalf("the push answered %d %s", rec.Code, rec.Body.String())
	}
	if rec := authorize(url.Values{"client_id": {f.clientID}, "request_uri": {pushed.RequestURI}}); refused(rec) ||
		rec.Code >= 400 {
		body := rec.Body.String()
		if i := strings.Index(body, "<main"); i >= 0 {
			body = body[i:]
		}
		t.Errorf("the pushed request answered %d %.600s", rec.Code, body)
	}
}

// A client set first-party skips the consent screen, and setting it back
// shows it again. The column had a reader and no writer (2.23).
func TestAFirstPartyClientSkipsConsentOnceSet(t *testing.T) {
	f := newTokenFixture(t)
	r := httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil)
	prompts := func() bool {
		t.Helper()
		c, err := clients.Lookup(r.Context(), f.pool, f.clientID)
		if err != nil {
			t.Fatal(err)
		}
		_, prompt, err := f.srv.needsConsent(r, c, f.userID, oauth.AuthzRequest{Scope: "openid email"})
		if err != nil {
			t.Fatal(err)
		}
		return prompt
	}
	if !prompts() {
		t.Fatal("a client nobody consented to was not prompted for; this test shows nothing")
	}
	on, off := true, false
	if err := setClientSettings(t, f, store.ClientSettings{FirstParty: &on}); err != nil {
		t.Fatal(err)
	}
	if prompts() {
		t.Error("set first-party, the client still prompts for consent")
	}
	if err := setClientSettings(t, f, store.ClientSettings{FirstParty: &off}); err != nil {
		t.Fatal(err)
	}
	if !prompts() {
		t.Error("set back, the client no longer prompts for consent")
	}
}
