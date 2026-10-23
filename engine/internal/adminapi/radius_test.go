package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// A RADIUS device is registered, revoked and restored, and a group placed on
// a VLAN and taken off it, through the Admin API as `signari radius` does it
// (6.07): the secret sealed and never read back, a range covering every
// address refused in any spelling, and the VLAN bounded as RFC 3580 bounds it.
func TestRADIUSIsConfiguredThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org + "/radius-clients"
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
	const secret = "an-office-wifi-shared-secret"
	for _, bad := range []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"name": "wifi", "network": "10.0.0.0/24", "secret": "short"}, "invalid_secret"},
		{map[string]any{"name": "wifi", "network": "10.0.0.0", "secret": secret}, "invalid_network"},
		{map[string]any{"name": "wifi", "network": "0.0.0.0/0", "secret": secret}, "invalid_network"},
		{map[string]any{"name": "wifi", "network": "::ffff:0.0.0.0/96", "secret": secret}, "invalid_network"},
	} {
		if e := errorOf(http.MethodPost, base, bad.body, http.StatusBadRequest); e != bad.want {
			t.Errorf("%v answered %q, want %q", bad.body, e, bad.want)
		}
	}

	rec := call(t, s, http.MethodPost, base, testToken,
		map[string]any{"name": "wifi", "network": "::ffff:10.0.0.0/120", "secret": secret})
	var made struct{ ID, Network string }
	_ = json.Unmarshal(rec.Body.Bytes(), &made)
	if rec.Code != http.StatusCreated || made.Network != "10.0.0.0/24" {
		t.Fatalf("registering: %d %s", rec.Code, rec.Body.String())
	}
	var sealed []byte
	if err := s.db.QueryRow(ctx, `SELECT secret_enc FROM core.radius_clients WHERE id = $1::uuid`,
		made.ID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	// Sealed under the context the listener opens it with.
	if opened, err := s.root.Open(sealed, store.SealContextRADIUSSecret); err != nil || string(opened) != secret {
		t.Errorf("the stored secret opens to the one given: %v", err)
	}
	if e := errorOf(http.MethodPost, base, map[string]any{"name": "other", "network": "10.0.0.0/24", "secret": secret},
		http.StatusConflict); e != "already_exists" {
		t.Errorf("a second device for the range answered %q", e)
	}
	list := call(t, s, http.MethodGet, base, testToken, nil)
	if strings.Contains(list.Body.String(), secret) || !strings.Contains(list.Body.String(), `"network":"10.0.0.0/24"`) {
		t.Errorf("the devices read %s", list.Body.String())
	}

	enabled := func() bool {
		var on bool
		_ = s.db.QueryRow(ctx, `SELECT enabled FROM core.radius_clients WHERE id = $1::uuid`, made.ID).Scan(&on)
		return on
	}
	if rec := call(t, s, http.MethodPatch, base+"/"+made.ID, testToken, map[string]any{"enabled": false}); rec.Code != http.StatusOK || enabled() {
		t.Errorf("revoking answered %d and left it enabled %v", rec.Code, enabled())
	}
	if rec := call(t, s, http.MethodPatch, base+"/"+made.ID, testToken, map[string]any{"enabled": true}); rec.Code != http.StatusOK || !enabled() {
		t.Errorf("restoring answered %d and left it enabled %v", rec.Code, enabled())
	}
	// Another organisation's device is not this one's to revoke.
	other := newDriftMigrationOrg(t, s, false)
	theirs, _, err := store.AddRADIUSClient(ctx, s.db, s.root, other, "theirs", "10.9.0.0/24", secret)
	if err != nil {
		t.Fatal(err)
	}
	if e := errorOf(http.MethodPatch, base+"/"+theirs, map[string]any{"enabled": false},
		http.StatusNotFound); e != "radius_client_not_found" {
		t.Errorf("another organisation's device answered %q", e)
	}

	var group string
	if err := s.db.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name) VALUES ($1::uuid, $2, $2)
		RETURNING id::text`, org, fmt.Sprintf("staff-%d", time.Now().UnixNano())).Scan(&group); err != nil {
		t.Fatal(err)
	}
	auth := "/admin/groups/" + group + "/radius"
	for _, bad := range []map[string]any{{"priority": 5}, {"vlan_id": 4095}, {"filter_id": strings.Repeat("f", 254)}} {
		if e := errorOf(http.MethodPut, auth, bad, http.StatusBadRequest); e != "invalid_radius_authorization" {
			t.Errorf("%v answered %q", bad, e)
		}
	}
	if rec := call(t, s, http.MethodPut, auth, testToken, map[string]any{"vlan_id": 42, "filter_id": " staff ",
		"priority": 10}); rec.Code != http.StatusOK {
		t.Fatalf("authorising: %d %s", rec.Code, rec.Body.String())
	}
	got := call(t, s, http.MethodGet, "/admin/organizations/"+org+"/radius-authorizations", testToken, nil)
	if !strings.Contains(got.Body.String(), `"vlan_id":42`) || !strings.Contains(got.Body.String(), `"filter_id":"staff"`) {
		t.Errorf("the authorisations read %s", got.Body.String())
	}
	if rec := call(t, s, http.MethodDelete, auth, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("removing: %d", rec.Code)
	}
	if e := errorOf(http.MethodDelete, auth, nil, http.StatusNotFound); e != "radius_authorization_not_found" {
		t.Errorf("removing it twice answered %q", e)
	}
}

// A token narrowed to one group places that group on a VLAN and sees only
// its own authorisation; another group is not its to change.
func TestAGroupNarrowedTokenAuthorisesItsOwnGroupOnly(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	groups := make([]string, 2)
	for i := range groups {
		if err := s.db.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name) VALUES ($1::uuid, $2, $2)
			RETURNING id::text`, org, fmt.Sprintf("narrow-%d-%d", i, time.Now().UnixNano())).Scan(&groups[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetRADIUSAuthorization(ctx, s.db, org, groups[1], 7, "", 0); err != nil {
		t.Fatal(err)
	}
	narrowed, _, err := NewToken(ctx, s.db, "radius-narrowed-"+groups[0], org,
		[]string{ScopeGroupsWrite, ScopeConfigRead}, nil, nil, []string{groups[0]})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE token_hash = $1`, sha256Of(narrowed))
	})
	if rec := call(t, s, http.MethodPut, "/admin/groups/"+groups[0]+"/radius", narrowed,
		map[string]any{"vlan_id": 42}); rec.Code != http.StatusOK {
		t.Errorf("its own group answered %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodPut, "/admin/groups/"+groups[1]+"/radius", narrowed,
		map[string]any{"vlan_id": 99}); rec.Code == http.StatusOK {
		t.Error("a group outside the token was changed")
	}
	list := call(t, s, http.MethodGet, "/admin/organizations/"+org+"/radius-authorizations", narrowed, nil)
	if strings.Contains(list.Body.String(), groups[1]) || !strings.Contains(list.Body.String(), groups[0]) {
		t.Errorf("the narrowed token read %s", list.Body.String())
	}
	if rec := call(t, s, http.MethodPost, "/admin/organizations/"+org+"/radius-clients", narrowed,
		map[string]any{"name": "x", "network": "10.1.0.0/24", "secret": "an-office-wifi-shared-secret"}); rec.Code != http.StatusForbidden {
		t.Errorf("a narrowed token registering a device answered %d", rec.Code)
	}
}
