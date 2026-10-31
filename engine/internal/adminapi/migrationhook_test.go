package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/delegated"
)

type hookRoundTrip func(*http.Request) (*http.Response, error)

func (f hookRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A source of kind hook over the Admin API, from nothing to a test of it (10.07): it is
// refused until there is a provider, it takes the place of a source that held a secret,
// and the test asks the provider, with the operator's account, the way a sign-in will.
func TestAHookSourceCanBeConfiguredAndTestedOverTheAdminAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	path := "/admin/organizations/" + org + "/migration-source"
	send := func(method, p, body string) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, method, p, body, ""))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}

	hook := `{"kind":"hook","display_name":"Old system"}`
	if rec, out := send(http.MethodPut, path, hook); rec.Code != http.StatusBadRequest ||
		out["error"] != "invalid_migration_source" {
		t.Errorf("a hook source with no provider gave %d %v, want 400 invalid_migration_source", rec.Code, out)
	}
	if _, err := s.db.Exec(ctx, `
		INSERT INTO core.providers (org_id, name, hook, url, mode, timeout_ms)
		VALUES ($1::uuid, 'old-system', 'password_verify', 'https://old-system.test/verify', 'fail_closed', 2000)`,
		org); err != nil {
		t.Fatal(err)
	}
	if rec, out := send(http.MethodPut, path, `{"kind":"hook","display_name":"Old system",
		"url":"https://elsewhere.test/verify"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("a hook source naming its own endpoint gave %d %v, want 400: its provider holds that", rec.Code, out)
	}

	// Replacing a source that holds a client secret leaves none behind.
	if rec, out := send(http.MethodPut, path, `{"kind":"oidc_password","display_name":"Old IdP",
		"url":"https://old.example.com/token","client_id":"migration"}`); rec.Code != http.StatusOK {
		t.Fatalf("an oidc_password source gave %d %v", rec.Code, out)
	}
	if _, err := s.db.Exec(ctx, `UPDATE core.migration_sources SET client_secret_enc = '\x01' WHERE org_id = $1::uuid`,
		org); err != nil {
		t.Fatal(err)
	}
	if rec, out := send(http.MethodPut, path, hook); rec.Code != http.StatusOK || out["kind"] != "hook" {
		t.Fatalf("a hook source in place of one with a secret gave %d %v", rec.Code, out)
	}

	var asked map[string]string
	verdict := `{"verified":true}`
	s.outbound = func(time.Duration) *http.Client {
		return &http.Client{Transport: hookRoundTrip(func(r *http.Request) (*http.Response, error) {
			_ = json.NewDecoder(r.Body).Decode(&asked)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(verdict))}, nil
		})}
	}
	test := path + "/test"
	alice := `{"username":"alice","password":"correct horse"}`
	rec, out := send(http.MethodPost, test, alice)
	if rec.Code != http.StatusOK || out["ok"] != true {
		t.Errorf("a credential the provider verified gave %d %v", rec.Code, out)
	}
	if asked["username"] != "alice" || asked["password"] != "correct horse" || asked["org_id"] != org {
		t.Errorf("the provider was asked %v", asked)
	}
	verdict = `{"verified":false}`
	rec, out = send(http.MethodPost, test, alice)
	if rec.Code != http.StatusOK || out["ok"] != false || out["step"] != delegated.StepAnswer {
		t.Errorf("a credential the provider refused gave %d %v", rec.Code, out)
	}
	verdict = `{}`
	rec, out = send(http.MethodPost, test, alice)
	if rec.Code != http.StatusOK || out["ok"] != false || !strings.Contains(fmt.Sprint(out["detail"]), "verified") {
		t.Errorf("an answer that does not say gave %d %v", rec.Code, out)
	}
}
