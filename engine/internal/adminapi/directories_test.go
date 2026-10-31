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

// A number kept from the directory being replaced is set by hand, so a person's files
// stay theirs: below what is allocated, never a host's own, never somebody else's.
func TestAPosixNumberCanBeKept(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	person := func(name string) string {
		var id string
		if err := s.db.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, username)
			VALUES ($1::uuid, sha256(convert_to($1::text || $2, 'UTF8')), $2) RETURNING id::text`, org, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = s.db.Exec(ctx, `DELETE FROM core.users WHERE id = $1::uuid`, id) })
		return id
	}
	ada, bea := person("ada"), person("bea")
	set := func(id string, n, want int) {
		t.Helper()
		if rec := call(t, s, http.MethodPatch, "/admin/users/"+id, testToken, map[string]any{"posix_uid": n}); rec.Code != want {
			t.Errorf("setting %d: %d %s", n, rec.Code, rec.Body.String())
		}
	}
	set(ada, 1500, http.StatusOK)
	set(ada, 0, http.StatusBadRequest)
	set(ada, 999, http.StatusBadRequest)
	set(ada, 2000000000, http.StatusBadRequest)
	set(bea, 1500, http.StatusConflict)
	if body := call(t, s, http.MethodGet, "/admin/users/"+ada, testToken, nil).Body.String(); !strings.Contains(body, `"posix_uid":1500`) {
		t.Errorf("the person reads %s", body)
	}

	group := func(name string) string {
		var id string
		if err := s.db.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name) VALUES ($1::uuid, $2, $2)
			RETURNING id::text`, org, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	staff, eng := group("staff"), group("eng")
	setGroup := func(id string, n, want int) {
		t.Helper()
		if rec := call(t, s, http.MethodPatch, "/admin/groups/"+id, testToken, map[string]any{"posix_gid": n}); rec.Code != want {
			t.Errorf("setting %d: %d %s", n, rec.Code, rec.Body.String())
		}
	}
	setGroup(staff, 1500, http.StatusOK) // A group's numbers are their own.
	setGroup(staff, 500, http.StatusBadRequest)
	setGroup(eng, 1500, http.StatusConflict)
	if body := call(t, s, http.MethodGet, "/admin/groups/"+staff, testToken, nil).Body.String(); !strings.Contains(body, `"posix_gid":1500`) {
		t.Errorf("the group reads %s", body)
	}
}

// A map is set and cleared through the API as `dir set` does it, and one naming an
// attribute nobody declared is refused there rather than at a sync.
func TestAnAttributeMapIsSetThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftDirectory(t, s)
	if rec := call(t, s, http.MethodPut, "/admin/organizations/"+org+"/attributes", testToken, map[string]any{
		"name": "department", "display_name": "Department"}); rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("declaring: %d %s", rec.Code, rec.Body.String())
	}
	path := "/admin/organizations/" + org + "/directories/drift"
	patch := func(m map[string]string, want int) string {
		t.Helper()
		rec := call(t, s, http.MethodPatch, path, testToken, map[string]any{"attribute_map": m})
		if rec.Code != want {
			t.Fatalf("patching %v: %d %s", m, rec.Code, rec.Body.String())
		}
		return call(t, s, http.MethodGet, "/admin/organizations/"+org+"/directories", testToken, nil).Body.String()
	}
	if listed := patch(map[string]string{"departmentNumber": "department", "userPrincipalName": "email"},
		http.StatusOK); !strings.Contains(listed, `"departmentNumber":"department"`) {
		t.Errorf("the sources read %s", listed)
	}
	if listed := patch(map[string]string{"grade": "level"}, http.StatusBadRequest); !strings.Contains(listed,
		`"departmentNumber":"department"`) {
		t.Errorf("a refused map changed what was held: %s", listed)
	}
	if listed := patch(map[string]string{}, http.StatusOK); !strings.Contains(listed, `"attribute_map":{}`) {
		t.Errorf("an empty map left %s", listed)
	}
}

// Asking a directory whether it can be read is how a source is checked before it
// is turned on, so a disabled one answers; a directory that will not is an answer
// and not an error, and the record says how far it got and nothing it found.
func TestADirectoryIsAskedWhereItStops(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	closed := driftLDAPSource
	closed.LDAPURL = "ldaps://127.0.0.1:1"
	if _, err := directory.AddSource(ctx, s.db, s.root, org, closed); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `UPDATE core.directory_sources SET enabled = false
		WHERE org_id = $1::uuid AND slug = 'drift'`, org); err != nil {
		t.Fatal(err)
	}
	var before int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE org_id = $1::uuid
		AND event_type = 'admin.directory_tested'`, org).Scan(&before); err != nil {
		t.Fatal(err)
	}
	base := "/admin/organizations/" + org + "/directories"

	rec := call(t, s, http.MethodPost, base+"/drift/test", testToken, nil)
	var out struct {
		OK            bool   `json:"ok"`
		Step          string `json:"step"`
		Detail        string `json:"detail"`
		ConfigVersion int64  `json:"config_version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || out.OK || out.Step != "connect" || out.Detail == "" {
		t.Fatalf("a disabled source on a closed port: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("ETag") == "" || out.ConfigVersion == 0 {
		t.Errorf("the answer carries no version: %s", rec.Body.String())
	}

	s.directoryTest = func(context.Context, *pgxpool.Pool, *keys.RootKey, string, string) (directory.TestResult, error) {
		return directory.TestResult{OK: true, Server: "ldaps://dc02.example.test", Found: 5,
			Detail: "ada@example.test"}, nil
	}
	rec = call(t, s, http.MethodPost, base+"/drift/test", testToken, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) ||
		!strings.Contains(rec.Body.String(), `"found":5`) ||
		!strings.Contains(rec.Body.String(), `"server":"ldaps://dc02.example.test"`) {
		t.Errorf("a directory that answers: %d %s", rec.Code, rec.Body.String())
	}
	var details []string
	rows, err := s.db.Query(ctx, `SELECT detail::text FROM core.audit_events WHERE org_id = $1::uuid
		AND event_type = 'admin.directory_tested' ORDER BY id`, org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		details = append(details, d)
	}
	if len(details) != int(before)+2 {
		t.Fatalf("recorded %d, want %d more than %d", len(details), 2, before)
	}
	last := details[len(details)-1]
	if strings.Contains(last, "ada@example.test") || !strings.Contains(last, `"ok": true`) {
		t.Errorf("the record reads %s", last)
	}

	narrowed := narrowedToken(t, s, org, []string{ScopeOrganizationsWrite}, nil, []string{"00000000-0000-0000-0000-000000000001"})
	if rec := call(t, s, http.MethodPost, base+"/drift/test", narrowed, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a token limited to a group asked a directory: %d %s", rec.Code, rec.Body.String())
	}
	s.directoryTest = directory.TestSource
	if rec := call(t, s, http.MethodPost, base+"/elsewhere/test", testToken, nil); rec.Code != http.StatusNotFound ||
		!strings.Contains(rec.Body.String(), "source_not_found") {
		t.Errorf("an unknown source: %d %s", rec.Code, rec.Body.String())
	}
}
