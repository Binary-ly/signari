package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// A remote-access connection is registered, given parameters and taken out of
// service through the Admin API as `signari rac` does it (6.07): its
// credentials sealed and never read back, and nothing that chooses where the
// machine guacd runs on writes.
func TestARemoteAccessConnectionIsManagedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	if _, err := s.db.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, 'finance', 'Finance')`, org); err != nil {
		t.Fatal(err)
	}
	base := "/admin/organizations/" + org + "/rac-connections"
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
	const password = "a-desk-service-password"
	for _, bad := range []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"slug": "desk", "protocol": "telnet", "host": "10.0.4.21"}, "invalid_protocol"},
		{map[string]any{"slug": "desk", "protocol": "rdp", "host": "10.0.4.21", "require_group": "nobody"}, "unknown_group"},
		{map[string]any{"slug": "desk", "protocol": "rdp"}, "host_required"},
		{map[string]any{"slug": "desk", "protocol": "rdp", "host": "10.0.4.21", "recording_path": "/tmp"}, "invalid_json"},
	} {
		if e := errorOf(http.MethodPost, base, bad.body, http.StatusBadRequest); e != bad.want {
			t.Errorf("%v answered %q, want %q", bad.body, e, bad.want)
		}
	}

	rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"slug": "desk", "name": "Finance desktop",
		"protocol": "rdp", "host": "10.0.4.21", "login": "svc-desk", "password": password, "require_group": "finance"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering: %d %s", rec.Code, rec.Body.String())
	}
	// Sealed where the connect path opens it, with the protocol's own port.
	c, err := store.LoadRACConnection(ctx, s.db, org, "desk")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := c.Resolve(s.root, 1024, 768, 96)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Parameters["password"] != password || resolved.Parameters["username"] != "svc-desk" ||
		resolved.Parameters["port"] != "3389" || c.RequireGroup != "finance" || c.RecordingPath != "" {
		t.Errorf("the connection resolves to port %s, group %q, recording %q, credentials opened %v",
			resolved.Parameters["port"], c.RequireGroup, c.RecordingPath, resolved.Parameters["password"] == password)
	}
	if e := errorOf(http.MethodPost, base, map[string]any{"slug": "desk", "protocol": "ssh", "host": "bastion"},
		http.StatusConflict); e != "already_exists" {
		t.Errorf("a second connection of the slug answered %q", e)
	}

	for params, want := range map[string]string{
		`{"parameters":{"password":"hunter2"}}`:     "reserved_parameter",
		`{"parameters":{"hostname":"elsewhere"}}`:   "reserved_parameter",
		`{"parameters":{"drive-path":"/etc"}}`:      "parameter_names_a_path",
		`{"parameters":{"typescript-path":"/var"}}`: "parameter_names_a_path",
		`{"parameters":{"recording-path":"/root"}}`: "parameter_names_a_path",
		`{"parameters":{" ":"x"}}`:                  "invalid_parameter",
		`{}`:                                        "nothing_to_change",
	} {
		if e := errorOf(http.MethodPatch, base+"/desk", json.RawMessage(params), http.StatusBadRequest); e != want {
			t.Errorf("%s answered %q, want %q", params, e, want)
		}
	}
	if rec := call(t, s, http.MethodPatch, base+"/desk", testToken, map[string]any{"enabled": false,
		"parameters": map[string]string{"ignore-cert": "true"}}); rec.Code != http.StatusOK {
		t.Fatalf("disabling with parameters: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := store.LoadRACConnection(ctx, s.db, org, "desk"); err == nil {
		t.Error("a disabled connection still loads for connecting")
	}
	list := call(t, s, http.MethodGet, base, testToken, nil)
	if strings.Contains(list.Body.String(), password) || strings.Contains(list.Body.String(), "svc-desk") ||
		!strings.Contains(list.Body.String(), `"parameters":{"ignore-cert":"true"}`) ||
		!strings.Contains(list.Body.String(), `"has_credentials":true`) {
		t.Errorf("the connections read %s", list.Body.String())
	}
	if e := errorOf(http.MethodPatch, base+"/elsewhere", map[string]any{"enabled": true},
		http.StatusNotFound); e != "connection_not_found" {
		t.Errorf("an unknown connection answered %q", e)
	}
}
