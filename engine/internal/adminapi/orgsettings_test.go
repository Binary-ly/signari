package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// An organisation's settings are read and changed through the Admin API as
// the `instance` commands change them (6.07): every field the request takes is
// applied, a value out of bounds changes nothing, and each change is recorded.

// settingChoices are two valid values of each setting, so one differs from
// whatever is there.
var settingChoices = map[string][2]any{
	"max_concurrent_sessions": {3, 4}, "session_limit_behaviour": {"deny", "evict_oldest"},
	"password_only_binds": {"allow", "refuse_when_mfa"}, "remember_device_days": {7, 14},
	"new_device_notice": {true, false}, "reauth_window_s": {600, 900},
	"session_lifetime_s": {43200, 28800}, "session_idle_s": {1800, 3600},
	"offline_lifetime_s": {604800, 1209600}, "persistent_sessions": {true, false},
	"sms_numbers": {"stored", "hashed"}, "totp_algorithm": {"SHA1", "SHA256"},
	"totp_digits": {6, 8}, "totp_period_s": {30, 60},
	"login_free_attempts": {3, 5}, "login_max_delay_s": {900, 1800},
}

func TestEveryOrganisationSettingIsSetThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftMigrationOrg(t, s, false)
	path := "/admin/organizations/" + org + "/settings"
	read := func() map[string]any {
		t.Helper()
		rec := call(t, s, http.MethodGet, path, testToken, nil)
		var v map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("reading the settings: %d %s", rec.Code, rec.Body.String())
		}
		return v
	}

	// Every field the request takes, from the type: one added to it and not
	// here is named.
	rt := reflect.TypeOf(patchOrgSettingsRequest{})
	before := read()
	want := map[string]any{}
	for i := range rt.NumField() {
		key := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
		choice, ok := settingChoices[key]
		if !ok {
			t.Fatalf("the request takes %q and this test has no value for it", key)
		}
		// JSON numbers read back as float64.
		pickOne := choice[0]
		if equalJSON(before[key], choice[0]) {
			pickOne = choice[1]
		}
		want[key] = pickOne
	}

	rec := call(t, s, http.MethodPatch, path, testToken, want)
	if rec.Code != http.StatusOK {
		t.Fatalf("changing every setting: %d %s", rec.Code, rec.Body.String())
	}
	after := read()
	for key, v := range want {
		if !equalJSON(after[key], v) {
			t.Errorf("%s was asked to be %v and reads %v: the request took it and nothing applied it",
				key, v, after[key])
		}
	}

	// Out of bounds, alongside a good change: neither is made.
	for _, bad := range []map[string]any{
		{"remember_device_days": 1, "max_concurrent_sessions": -1},
		{"remember_device_days": 1, "session_limit_behaviour": "evict_newest"},
		{"remember_device_days": 1, "reauth_window_s": 5},
		{"remember_device_days": 1, "session_idle_s": 60},
		{"remember_device_days": 1, "sms_numbers": "plain"},
		{"remember_device_days": 1, "totp_digits": 7},
		{"remember_device_days": 1, "login_free_attempts": 0},
		{"remember_device_days": 1, "password_only_binds": "sometimes"},
		{"remember_device_days": 91},
	} {
		rec := call(t, s, http.MethodPatch, path, testToken, bad)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusBadRequest || out["error"] != "invalid_setting" {
			t.Errorf("%v answered %d %v", bad, rec.Code, out)
		}
	}
	if got := read(); !equalJSON(got["remember_device_days"], want["remember_device_days"]) {
		t.Errorf("a refused change changed remember_device_days to %v", got["remember_device_days"])
	}

	// Each recorded as its command records it.
	var n int
	if err := s.db.QueryRow(context.Background(), `SELECT count(*) FROM core.audit_events
		WHERE org_id = $1::uuid AND event_type LIKE 'org.%' AND detail->>'via' = 'admin_api'`, org).Scan(&n); err != nil {
		t.Fatal(err)
	}
	// Session limit, binds, devices, notice, window, lifetimes, numbers, TOTP, throttle.
	if n != 9 {
		t.Errorf("changing every setting was recorded %d times, want 9", n)
	}
}

func equalJSON(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}
