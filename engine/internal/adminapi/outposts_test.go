package adminapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// An outpost is registered, given a search group, taken out of service and
// put back through the Admin API as `signari outpost` does it (6.07): its
// token shown once and stored hashed, and a search group refused where it
// would mean nothing.
func TestAnOutpostIsManagedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	if _, err := s.db.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, 'ldap-readers', 'LDAP readers')`, org); err != nil {
		t.Fatal(err)
	}
	base := "/admin/organizations/" + org + "/outposts"
	errorOf := func(method, path string, body any, want int) string {
		t.Helper()
		rec := call(t, s, method, path, testToken, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Errorf("%s %s %v answered %d, want %d: %s", method, path, body, rec.Code, want, rec.Body.String())
		}
		e, _ := out["error"].(string)
		return e
	}
	for body, want := range map[string]string{
		`{"name":"dmz","kind":"kerberos"}`:                             "invalid_kind",
		`{"name":"dmz","kind":"radius","search_group":"ldap-readers"}`: "invalid_search_group",
		`{"name":"dmz","kind":"ldap","search_group":"nobody-here"}`:    "invalid_search_group",
		`{"name":" ","kind":"ldap"}`:                                   "name_required",
	} {
		if e := errorOf(http.MethodPost, base, json.RawMessage(body), http.StatusBadRequest); e != want {
			t.Errorf("%s answered %q, want %q", body, e, want)
		}
	}

	rec := call(t, s, http.MethodPost, base, testToken,
		map[string]any{"name": "dmz", "kind": "ldap", "search_group": "ldap-readers"})
	var made struct{ ID, Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &made)
	if rec.Code != http.StatusCreated || made.Token == "" {
		t.Fatalf("registering: %d %s", rec.Code, rec.Body.String())
	}
	var hash []byte
	var group string
	if err := s.db.QueryRow(ctx, `SELECT token_hash, COALESCE(search_group, '') FROM core.outposts
		WHERE id = $1::uuid`, made.ID).Scan(&hash, &group); err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256([]byte(made.Token)); !bytes.Equal(hash, sum[:]) || group != "ldap-readers" {
		t.Errorf("the outpost was stored with a hash matching its token %v and search group %q",
			bytes.Equal(hash, sum[:]), group)
	}
	if e := errorOf(http.MethodPost, base, map[string]any{"name": "dmz", "kind": "radius"},
		http.StatusConflict); e != "already_exists" {
		t.Errorf("a second outpost of the name answered %q", e)
	}
	list := call(t, s, http.MethodGet, base, testToken, nil)
	if strings.Contains(list.Body.String(), made.Token) || !strings.Contains(list.Body.String(), `"search_group":"ldap-readers"`) {
		t.Errorf("the outposts read %s", list.Body.String())
	}

	state := func() (enabled bool, group string) {
		if err := s.db.QueryRow(ctx, `SELECT enabled, COALESCE(search_group, '') FROM core.outposts
			WHERE id = $1::uuid`, made.ID).Scan(&enabled, &group); err != nil {
			t.Fatal(err)
		}
		return
	}
	if rec := call(t, s, http.MethodPatch, base+"/dmz", testToken, map[string]any{"enabled": false,
		"search_group": ""}); rec.Code != http.StatusOK {
		t.Fatalf("disabling: %d %s", rec.Code, rec.Body.String())
	}
	if enabled, group := state(); enabled || group != "" {
		t.Errorf("a disabled outpost with its search group cleared reads enabled %v, group %q", enabled, group)
	}
	// One refused change leaves the other undone too.
	if e := errorOf(http.MethodPatch, base+"/dmz", map[string]any{"enabled": true, "search_group": "nobody-here"},
		http.StatusBadRequest); e != "invalid_search_group" {
		t.Errorf("an unknown search group answered %q", e)
	}
	if enabled, _ := state(); enabled {
		t.Error("a refused change switched the outpost back on")
	}
	if rec := call(t, s, http.MethodPatch, base+"/dmz", testToken, map[string]any{"enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("enabling: %d", rec.Code)
	}
	if enabled, _ := state(); !enabled {
		t.Error("an enabled outpost is still off")
	}
	if e := errorOf(http.MethodPatch, base+"/dmz", map[string]any{}, http.StatusBadRequest); e != "nothing_to_change" {
		t.Errorf("an empty change answered %q", e)
	}
	if e := errorOf(http.MethodPatch, base+"/elsewhere", map[string]any{"enabled": false},
		http.StatusNotFound); e != "outpost_not_found" {
		t.Errorf("an unknown outpost answered %q", e)
	}
}
