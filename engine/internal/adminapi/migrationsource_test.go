package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newDriftMigrationOrg is an organisation of its own, removed with the test,
// holding a migration source when withSource is set.
func newDriftMigrationOrg(t *testing.T, s *Server, withSource bool) string {
	t.Helper()
	ctx := context.Background()
	var org string
	if err := s.db.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, $1, 'migration drift' FROM core.organizations WHERE id = $2::uuid
		RETURNING id::text`, fmt.Sprintf("migdrift-%d", time.Now().UnixNano()), anyOrgID(t, s)).Scan(&org); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.organizations WHERE id = $1::uuid`, org)
	})
	if withSource {
		if _, err := s.db.Exec(ctx, `
			INSERT INTO core.migration_sources (org_id, kind, display_name, token_endpoint, bind_dn_template)
			VALUES ($1::uuid, 'ldap', 'drift', 'ldaps://dir.example.test', 'uid={username},dc=example')`, org); err != nil {
			t.Fatal(err)
		}
	}
	return org
}

// The migration source can be configured over the Admin API (2.01), as the
// CLI configures it: created disabled, switched by `enabled`, read back
// without its secret, refused when the verifier would refuse it, and removed.
// Nothing could create one before, by any route.
func TestAMigrationSourceCanBeConfiguredOverTheAdminAPI(t *testing.T) {
	s, pool := newTestServer(t)
	ctx := context.Background()

	var org string
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, $1, 'migration api' FROM core.instances ORDER BY created_at LIMIT 1
		RETURNING id::text`, fmt.Sprintf("migapi-%d", time.Now().UnixNano())).Scan(&org); err != nil {
		t.Skipf("no instance to create an organisation in: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM core.organizations WHERE id = $1::uuid`, org)
	})
	path := "/admin/organizations/" + org + "/migration-source"
	call := func(method, body string) (int, map[string]any) {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, method, path, body, ""))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	if code, _ := call(http.MethodGet, ""); code != http.StatusNotFound {
		t.Fatalf("GET with no source gave %d, want 404", code)
	}
	code, out := call(http.MethodPut, `{"kind":"oidc_password","display_name":"Old IdP",
		"url":"https://old.example.test/token","client_id":"migration","client_secret":"s3cret"}`)
	if code != http.StatusOK || out["enabled"] != false || out["has_client_secret"] != true {
		t.Fatalf("PUT gave %d %v; want a disabled source holding a secret", code, out)
	}
	code, out = call(http.MethodPut, `{"kind":"oidc_password","display_name":"Old IdP",
		"url":"https://old.example.test/token","client_id":"migration","enabled":true}`)
	if code != http.StatusOK || out["enabled"] != true || out["has_client_secret"] != true {
		t.Errorf("a PUT with no secret and enabled gave %d %v; want it enabled and the secret kept", code, out)
	}
	// The stored secret was issued for this endpoint and client id (1.89):
	// repointing either without a new secret is refused, and the source stays
	// as it was, rather than sending the old secret to the new endpoint.
	for _, moved := range []string{
		`{"kind":"oidc_password","display_name":"Old IdP","url":"https://elsewhere.example.test/token","client_id":"migration"}`,
		`{"kind":"oidc_password","display_name":"Old IdP","url":"https://old.example.test/token","client_id":"another"}`,
	} {
		if code, out := call(http.MethodPut, moved); code != http.StatusBadRequest || out["error"] != "invalid_migration_source" {
			t.Errorf("PUT %s with no secret gave %d %v; want 400 invalid_migration_source", moved, code, out)
		}
	}
	if code, out := call(http.MethodGet, ""); code != http.StatusOK || out["url"] != "https://old.example.test/token" {
		t.Errorf("after the refused moves the source is %d %v; want it unchanged", code, out)
	}
	code, out = call(http.MethodPut, `{"kind":"oidc_password","display_name":"Old IdP",
		"url":"https://elsewhere.example.test/token","client_id":"migration","client_secret":"n3w"}`)
	if code != http.StatusOK || out["url"] != "https://elsewhere.example.test/token" || out["has_client_secret"] != true {
		t.Errorf("moving it with a new secret gave %d %v; want it moved, holding the new secret", code, out)
	}
	code, out = call(http.MethodGet, "")
	raw, _ := json.Marshal(out)
	if code != http.StatusOK || strings.Contains(string(raw), "s3cret") || strings.Contains(string(raw), "secret_enc") {
		t.Errorf("GET gave %d %s; want the source without its secret", code, raw)
	}

	for _, bad := range []string{
		`{"kind":"ldap","display_name":"d","url":"ldap://dir.example.test","bind_dn_template":"uid={username},dc=x"}`,
		`{"kind":"ldap","display_name":"d","url":"ldaps://dir.example.test","bind_dn_template":"cn=admin,dc=x"}`,
		`{"kind":"oidc_password","display_name":"d","url":"http://old.example.test/token","client_id":"c"}`,
		`{"kind":"kerberos","display_name":"d","url":"ldaps://dir.example.test"}`,
	} {
		if code, out := call(http.MethodPut, bad); code != http.StatusBadRequest || out["error"] != "invalid_migration_source" {
			t.Errorf("PUT %s gave %d %v; want 400 invalid_migration_source", bad, code, out)
		}
	}
	code, out = call(http.MethodPut, `{"kind":"ldap","display_name":"Old directory","url":"ldaps://dir.example.test",
		"bind_dn_template":"uid={username},ou=people,dc=example"}`)
	if code != http.StatusOK || out["kind"] != "ldap" || out["has_client_secret"] != false || out["enabled"] != true {
		t.Errorf("replacing it with a directory gave %d %v; want ldap, still enabled, and no secret", code, out)
	}

	if code, _ := call(http.MethodDelete, ""); code != http.StatusOK {
		t.Errorf("DELETE gave %d", code)
	}
	if code, _ := call(http.MethodGet, ""); code != http.StatusNotFound {
		t.Errorf("GET after DELETE gave %d, want 404", code)
	}
}
