package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"signari.dev/engine/internal/store"
)

// Duo is configured and people enrolled through the Admin API as `signari duo
// set|enroll` does it (6.07): the keys are checked against Duo before anything
// is stored, its secret is never read back, and a person is enrolled only in
// an organisation whose Duo works.
func TestDuoIsConfiguredAndPeopleEnrolledThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	var healthy atomic.Bool
	stand := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/v1/health_check" {
			http.NotFound(w, r)
			return
		}
		if healthy.Load() {
			_, _ = w.Write([]byte(`{"stat":"OK"}`))
			return
		}
		_, _ = w.Write([]byte(`{"stat":"FAIL","message":"invalid client","code":40301}`))
	}))
	t.Cleanup(stand.Close)
	t.Setenv("SIGNARI_DUO_BASE_URL", stand.URL)
	t.Setenv("SIGNARI_INSECURE_ISSUER", "1")

	path := "/admin/organizations/" + org + "/duo"
	secret := strings.Repeat("s", 40)
	keys := map[string]any{"client_id": "DIABCDEFGHIJKLMNOPQR", "secret": secret,
		"api_host": "api-1234abcd.duosecurity.com"}
	errorOf := func(body map[string]any) string {
		t.Helper()
		rec := call(t, s, http.MethodPut, path, testToken, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%v answered %d", body, rec.Code)
		}
		e, _ := out["error"].(string)
		return e
	}
	if e := errorOf(map[string]any{"client_id": "short", "secret": secret, "api_host": "api-1.duosecurity.com"}); e != "invalid_duo" {
		t.Errorf("a short integration key answered %q", e)
	}
	if e := errorOf(map[string]any{"client_id": "DIABCDEFGHIJKLMNOPQR", "secret": secret, "api_host": "duo.attacker.example"}); e != "invalid_duo" {
		t.Errorf("a host outside Duo answered %q", e)
	}
	if e := errorOf(keys); e != "duo_check_failed" {
		t.Errorf("keys Duo refuses answered %q", e)
	}
	if d, _ := store.DuoIntegrationOf(ctx, s.db, org); d.Configured {
		t.Fatal("keys Duo refused were stored")
	}

	person := personIn(t, s, org)
	if rec := call(t, s, http.MethodPut, "/admin/users/"+person+"/duo", testToken,
		map[string]any{"duo_username": "ada"}); rec.Code != http.StatusConflict {
		t.Errorf("enrolling before Duo is configured answered %d", rec.Code)
	}

	healthy.Store(true)
	if rec := call(t, s, http.MethodPut, path, testToken, keys); rec.Code != http.StatusOK {
		t.Fatalf("configuring Duo: %d %s", rec.Code, rec.Body.String())
	}
	rec := call(t, s, http.MethodGet, path, testToken, nil)
	if strings.Contains(rec.Body.String(), secret) || !strings.Contains(rec.Body.String(), `"configured":true`) {
		t.Errorf("the integration reads %s", rec.Body.String())
	}
	// What a sign-in unseals and uses.
	cfg, err := store.LoadDuoIntegration(ctx, s.db, org, s.root, "https://idp.example.test/login/duo/callback", true)
	if err != nil || cfg.ClientSecret != secret {
		t.Errorf("the sign-in path's integration is %+v (%v)", cfg, err)
	}

	if rec := call(t, s, http.MethodPut, "/admin/users/"+person+"/duo", testToken,
		map[string]any{"duo_username": "ada"}); rec.Code != http.StatusOK {
		t.Fatalf("enrolling: %d %s", rec.Code, rec.Body.String())
	}
	var enrolled string
	if err := s.db.QueryRow(ctx, `SELECT duo_username FROM core.duo_enrollments WHERE user_id = $1::uuid`,
		person).Scan(&enrolled); err != nil || enrolled != "ada" {
		t.Errorf("the enrolment is %q (%v)", enrolled, err)
	}
}

// healthyDuo points Duo at a stand-in that passes every health check, for the
// rest of the test.
func healthyDuo(t *testing.T) {
	t.Helper()
	stand := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"stat":"OK"}`))
	}))
	t.Cleanup(stand.Close)
	t.Setenv("SIGNARI_DUO_BASE_URL", stand.URL)
	t.Setenv("SIGNARI_INSECURE_ISSUER", "1")
}

// duoKeys are keys of the shape Duo issues.
const duoKeys = `{"client_id":"DIABCDEFGHIJKLMNOPQR","secret":"ssssssssssssssssssssssssssssssssssssssss",` +
	`"api_host":"api-1234abcd.duosecurity.com"}`

// personIn is a person of the given organisation.
func personIn(t *testing.T, s *Server, orgID string) string {
	t.Helper()
	var id string
	if err := s.db.QueryRow(context.Background(), `INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, sha256(convert_to(gen_random_uuid()::text, 'UTF8')) || sha256(convert_to(gen_random_uuid()::text, 'UTF8')),
		        'p-' || gen_random_uuid() || '@example.test') RETURNING id::text`, orgID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, id) })
	return id
}
