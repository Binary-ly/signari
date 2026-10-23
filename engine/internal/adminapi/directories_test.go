package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/directory"
	"signari.dev/engine/internal/keys"
)

// driftLDAPSource is an LDAP source the fixtures register; nothing dials it.
var driftLDAPSource = directory.SourceSpec{Kind: "ldap", Slug: "drift", LDAPURL: "ldaps://ldap.example.test",
	LDAPBindDN: "cn=reader,dc=example,dc=test", LDAPPassword: "a-bind-password", LDAPBaseDN: "dc=example,dc=test",
	LDAPFlavour: "openldap", LDAPStartTLS: true}

// newDriftDirectory is an organisation of the test's own with the drift
// LDAP source and a group named drift-group.
func newDriftDirectory(t *testing.T, s *Server) string {
	t.Helper()
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	if _, err := directory.AddSource(ctx, s.db, s.root, org, driftLDAPSource); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, 'drift-group', 'Drift group')`, org); err != nil {
		t.Fatal(err)
	}
	return org
}

// standInDirectory replaces the directory a sync would call with one that
// reports what it is given, and records what it was asked.
func standInDirectory(s *Server, report directory.SyncReport, err error) *[]bool {
	var asked []bool
	s.directorySync = func(_ context.Context, _ *pgxpool.Pool, _ *keys.RootKey, _, _ string, apply bool) (
		directory.SyncReport, error) {
		asked = append(asked, apply)
		return report, err
	}
	return &asked
}

// A directory source is registered, tuned, given a group mapping and synced
// through the Admin API as `signari dir` does it (6.07): its credentials
// sealed and never read back, an LDAP source left to a deployment-wide token,
// and a mapping onto a group whose members may impersonate refused.
func TestADirectorySourceIsManagedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org + "/directories"
	errorOf := func(token, method, path string, body any, want int) string {
		t.Helper()
		rec := call(t, s, method, path, token, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Errorf("%s %s %v answered %d, want %d: %s", method, path, body, rec.Code, want, rec.Body.String())
		}
		e, _ := out["error"].(string)
		return e
	}
	ldap := map[string]any{"kind": "ldap", "slug": "corp", "ldap_url": "ldaps://ldap.example.test",
		"ldap_bind_dn": "cn=reader,dc=example,dc=test", "ldap_password": "a-bind-password",
		"ldap_base_dn": "dc=example,dc=test", "ldap_flavour": "ad"}
	for _, bad := range []map[string]any{
		{"kind": "ldap", "slug": "corp", "ldap_url": "ldap://ldap.example.test", "ldap_base_dn": "dc=x",
			"ldap_flavour": "ad", "ldap_start_tls": false},
		{"kind": "ldap", "slug": "corp", "ldap_url": "ldaps://ldap.example.test", "ldap_base_dn": "dc=x",
			"ldap_flavour": "made-up"},
		{"kind": "google", "slug": "corp", "credentials": map[string]any{}},
		{"kind": "okapi", "slug": "corp"},
	} {
		if e := errorOf(testToken, http.MethodPost, base, bad, http.StatusBadRequest); e != "invalid_source" {
			t.Errorf("%v answered %q", bad, e)
		}
	}
	// The engine dials an LDAP URL from inside its network, so an
	// organisation's token does not choose one.
	orgToken := mintToken(t, s, "directory-org-scoped", org, []string{ScopeOrganizationsWrite, ScopeConfigRead}, nil)
	if e := errorOf(orgToken, http.MethodPost, base, ldap, http.StatusForbidden); e != "outside_token_organisation" {
		t.Errorf("an organisation's token registering an LDAP source answered %q", e)
	}
	rec := call(t, s, http.MethodPost, base, testToken, ldap)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"dry_run":true`) {
		t.Fatalf("registering: %d %s", rec.Code, rec.Body.String())
	}
	var sealed []byte
	if err := s.db.QueryRow(ctx, `SELECT credentials_enc FROM core.directory_sources WHERE org_id = $1::uuid AND slug = 'corp'`,
		org).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if opened, err := s.root.Open(sealed, directory.SealContextCredentials); err != nil || string(opened) != "a-bind-password" {
		t.Errorf("the stored bind password opens to the one given: %v", err)
	}
	if e := errorOf(testToken, http.MethodPost, base, ldap, http.StatusConflict); e != "already_exists" {
		t.Errorf("a second source of the slug answered %q", e)
	}

	// Tuned: one setting changed leaves the ceiling where it was.
	if e := errorOf(testToken, http.MethodPatch, base+"/corp", map[string]any{"max_deactivate_percent": 101},
		http.StatusBadRequest); e != "invalid_source" {
		t.Errorf("a ceiling over 100 answered %q", e)
	}
	if rec := call(t, s, http.MethodPatch, base+"/corp", orgToken, map[string]any{"max_deactivate_percent": 5}); rec.Code != http.StatusOK {
		t.Fatalf("setting the ceiling: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodPatch, base+"/corp", orgToken, map[string]any{"on_missing": "deactivate"}); rec.Code != http.StatusOK {
		t.Fatalf("setting on_missing: %d %s", rec.Code, rec.Body.String())
	}
	var ceiling int
	var onMissing string
	_ = s.db.QueryRow(ctx, `SELECT max_deactivate_percent, on_missing FROM core.directory_sources
		WHERE org_id = $1::uuid AND slug = 'corp'`, org).Scan(&ceiling, &onMissing)
	if ceiling != 5 || onMissing != "deactivate" {
		t.Errorf("the source reads ceiling %d, on_missing %q", ceiling, onMissing)
	}

	// Mapped onto an ordinary group, and refused onto one that impersonates.
	if _, err := s.db.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name, may_impersonate)
		VALUES ($1::uuid, 'staff', 'Staff', false), ($1::uuid, 'support', 'Support', true)`, org); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, s, http.MethodPut, base+"/corp/group-map", orgToken, map[string]string{"remote_group": "cn=staff",
		"group": "staff"}); rec.Code != http.StatusOK {
		t.Fatalf("mapping: %d %s", rec.Code, rec.Body.String())
	}
	if e := errorOf(testToken, http.MethodPut, base+"/corp/group-map", map[string]string{"remote_group": "cn=support",
		"group": "support"}, http.StatusConflict); e != "group_impersonates" {
		t.Errorf("mapping onto an impersonating group answered %q", e)
	}
	if e := errorOf(testToken, http.MethodPut, base+"/corp/group-map", map[string]string{"remote_group": "cn=x",
		"group": "nobody"}, http.StatusNotFound); e != "group_not_found" {
		t.Errorf("mapping onto an unknown group answered %q", e)
	}
	list := call(t, s, http.MethodGet, base, testToken, nil)
	if strings.Contains(list.Body.String(), "a-bind-password") ||
		!strings.Contains(list.Body.String(), `{"group":"staff","remote_group":"cn=staff"}`) {
		t.Errorf("the sources read %s", list.Body.String())
	}
	unmap := base + "/corp/group-map?remote_group=cn%3Dstaff&group=staff"
	if rec := call(t, s, http.MethodDelete, unmap, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("unmapping: %d %s", rec.Code, rec.Body.String())
	}
	if e := errorOf(testToken, http.MethodDelete, unmap, nil, http.StatusNotFound); e != "mapping_not_found" {
		t.Errorf("unmapping it again answered %q", e)
	}

	// A sync, with a stand-in for the directory: the answer carries its plan,
	// and a plan past the ceiling is refused.
	asked := standInDirectory(s, directory.SyncReport{Upstream: 3, ActiveBefore: 2, Plan: "  + create ada\n"}, nil)
	rec = call(t, s, http.MethodPost, base+"/corp/sync", orgToken, map[string]any{"apply": false})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"upstream":3`) || len(*asked) != 1 || (*asked)[0] {
		t.Errorf("previewing: %d %s, asked %v", rec.Code, rec.Body.String(), *asked)
	}
	standInDirectory(s, directory.SyncReport{Plan: "  - deactivate everybody\n"}, directory.ErrSyncRefused)
	if e := errorOf(testToken, http.MethodPost, base+"/corp/sync", map[string]any{"apply": true},
		http.StatusConflict); e != "sync_refused" {
		t.Errorf("a refused plan answered %q", e)
	}
	standInDirectory(s, directory.SyncReport{}, directory.ErrSourceUnknown)
	if e := errorOf(testToken, http.MethodPost, base+"/elsewhere/sync", map[string]any{"apply": true},
		http.StatusNotFound); e != "source_not_found" {
		t.Errorf("an unknown source answered %q", e)
	}
}
