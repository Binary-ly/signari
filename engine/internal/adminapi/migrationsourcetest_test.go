package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/delegated"
	"signari.dev/engine/internal/delegated/ldaptest"
	"signari.dev/engine/internal/safedial"
)

// A migration source can be tested before it is enabled (7.18): the step that
// failed is named, with the directory's result code, so a wrong template is
// seen by the operator who chose the account and not by the first person to
// sign in. The test changes nothing about the source, and its record holds
// the outcome, never the account it asked about.
func TestAMigrationSourceCanBeTestedBeforeItIsEnabled(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	dirURL, caPEM, binds, _ := ldaptest.Directory(t, "uid=alice,ou=people,dc=example", "correct horse")
	if err := safedial.AllowPrivate("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = safedial.AllowPrivate("") })

	path := "/admin/organizations/" + org + "/migration-source"
	send := func(method, p, body, ifMatch string) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, method, p, body, ifMatch))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}
	source := func(template string) {
		t.Helper()
		ca, _ := json.Marshal(caPEM)
		if rec, out := send(http.MethodPut, path, fmt.Sprintf(`{"kind":"ldap","display_name":"Old directory",
			"url":%q,"bind_dn_template":%q,"ca_pem":%s}`, dirURL, template, ca), ""); rec.Code != http.StatusOK {
			t.Fatalf("PUT gave %d %v", rec.Code, out)
		}
	}
	test := path + "/test"
	alice := `{"username":"alice","password":"correct horse"}`

	if rec, out := send(http.MethodPost, test, alice, ""); rec.Code != http.StatusNotFound {
		t.Errorf("a test with no source gave %d %v, want 404", rec.Code, out)
	}

	source("cn={username},ou=staff,dc=example")
	rec, out := send(http.MethodPost, test, alice, "")
	if rec.Code != http.StatusOK || out["ok"] != false || out["step"] != delegated.StepBind ||
		!strings.Contains(fmt.Sprint(out["detail"]), "Invalid Credentials") {
		t.Errorf("a wrong template gave %d %v; want the bind step, with the directory's answer", rec.Code, out)
	}
	if got := binds(); len(got) != 1 || got[0] != "cn=alice,ou=staff,dc=example" {
		t.Errorf("the directory saw binds %q; want the one the template made", got)
	}

	source("uid={username},ou=people,dc=example")
	rec, out = send(http.MethodPost, test, alice, "")
	version, _ := out["config_version"].(float64)
	if rec.Code != http.StatusOK || out["ok"] != true || out["step"] != "" {
		t.Errorf("the right template gave %d %v; want ok", rec.Code, out)
	}
	if got := rec.Header().Get("ETag"); version == 0 || got != etag(int64(version)) {
		t.Errorf("ETag %q for config_version %v; want the version the test was recorded at", got, out["config_version"])
	}
	if rec, out := send(http.MethodPost, test, `{"username":"alice","password":"wrong"}`, ""); rec.Code != http.StatusOK ||
		out["ok"] != false || out["step"] != delegated.StepBind {
		t.Errorf("a wrong password gave %d %v; want the bind step", rec.Code, out)
	}

	// Asked only of the account it was given, and never with an empty password.
	for _, body := range []string{`{"username":"alice"}`, `{"password":"correct horse"}`, `not json`} {
		if rec, out := send(http.MethodPost, test, body, ""); rec.Code != http.StatusBadRequest {
			t.Errorf("%s gave %d %v, want 400", body, rec.Code, out)
		}
	}
	// A precondition is honoured, as on every other write.
	if rec, out := send(http.MethodPost, test, alice, etag(1)); rec.Code != http.StatusPreconditionFailed {
		t.Errorf("a stale If-Match gave %d %v, want 412", rec.Code, out)
	}

	// Nothing about the source changed: it was created disabled and stays so.
	if rec, out := send(http.MethodGet, path, "", ""); rec.Code != http.StatusOK || out["enabled"] != false ||
		out["bind_dn_template"] != "uid={username},ou=people,dc=example" {
		t.Errorf("after the tests the source is %d %v; want it as configured, still disabled", rec.Code, out)
	}

	var n int
	var details string
	if err := s.db.QueryRow(ctx, `
		SELECT count(*), coalesce(string_agg(detail::text, ' '), '') FROM core.audit_events
		WHERE event_type = 'admin.migration_source_tested' AND org_id = $1::uuid`, org).Scan(&n, &details); err != nil {
		t.Fatal(err)
	}
	if n != 3 || !strings.Contains(details, `"step": "bind"`) || !strings.Contains(details, `"ok": true`) {
		t.Errorf("%d test records %s; want the three that ran, each with its outcome", n, details)
	}
	if strings.Contains(details, "alice") || strings.Contains(details, "horse") {
		t.Errorf("the record of a test names the account or its password: %s", details)
	}
}

// A token endpoint's test is sent the stored client secret, opened, as
// sign-in sends it, so a secret that was rotated at the old provider shows up
// as OUR client refused rather than as a person's wrong password.
func TestATokenEndpointIsTestedWithTheStoredSecret(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftMigrationOrg(t, s, false)
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		id, secret, _ := r.BasicAuth()
		if id == "" {
			id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		switch {
		case id != "migration" || secret != "s3cret":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid_client"}`)
		case r.PostForm.Get("password") != "correct horse":
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
		default:
			fmt.Fprint(w, `{"access_token":"x","token_type":"Bearer"}`)
		}
	}))
	t.Cleanup(idp.Close)
	s.verify = delegated.NewWithClient(idp.Client())

	path := "/admin/organizations/" + org + "/migration-source"
	send := func(method, p, body string) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, method, p, body, ""))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s gave %d %v", method, p, rec.Code, out)
		}
		return out
	}
	configure := func(secret string) {
		send(http.MethodPut, path, fmt.Sprintf(`{"kind":"oidc_password","display_name":"Old IdP",
			"url":%q,"client_id":"migration","client_secret":%q}`, idp.URL+"/token", secret))
	}

	configure("s3cret")
	if out := send(http.MethodPost, path+"/test", `{"username":"alice","password":"correct horse"}`); out["ok"] != true {
		t.Errorf("the stored secret and the right password: %v", out)
	}
	if out := send(http.MethodPost, path+"/test", `{"username":"alice","password":"wrong"}`); out["ok"] != false ||
		out["step"] != delegated.StepAnswer || strings.Contains(fmt.Sprint(out["detail"]), "OUR client") {
		t.Errorf("a wrong password: %v; want the answer step, refusing the person", out)
	}
	configure("rotated")
	if out := send(http.MethodPost, path+"/test", `{"username":"alice","password":"correct horse"}`); out["ok"] != false ||
		out["step"] != delegated.StepAnswer || !strings.Contains(fmt.Sprint(out["detail"]), "OUR client") {
		t.Errorf("a secret the provider no longer holds: %v; want OUR client refused", out)
	}
}
