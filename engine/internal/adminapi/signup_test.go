package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"signari.dev/engine/internal/store"
)

// Self-sign-up is opened, narrowed and closed through the Admin API as
// `signari signup` does it (6.07), and the rule written is the one the sign-up
// page reads: nobody before, the named domain after, nobody again once closed.
func TestSelfSignUpIsOpenedAndClosedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	path := "/admin/organizations/" + org + "/signup"
	permits := func(addr string) bool {
		t.Helper()
		rule, err := store.LoadSignupRule(ctx, s.db, org)
		if err != nil {
			t.Fatal(err)
		}
		return rule.Permits(addr)
	}
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

	if permits("someone@example.com") {
		t.Fatal("a new organisation admits self-sign-up")
	}
	// Leaving the domains off does not open it to every address.
	if e := errorOf(map[string]any{}); e != "invalid_rule" {
		t.Errorf("no domains answered %q", e)
	}
	if e := errorOf(map[string]any{"allowed_domains": []string{"example.com"}, "any_domain": true}); e != "invalid_rule" {
		t.Errorf("domains and any_domain together answered %q", e)
	}
	if e := errorOf(map[string]any{"allowed_domains": []string{"example.com"},
		"default_groups": []string{"no-such-group"}}); e != "unknown_group" {
		t.Errorf("a default group nobody has answered %q", e)
	}
	if permits("someone@example.com") {
		t.Fatal("a refused rule opened sign-up")
	}

	if rec := call(t, s, http.MethodPut, path, testToken,
		map[string]any{"allowed_domains": []string{" Example.COM "}}); rec.Code != http.StatusOK {
		t.Fatalf("opening sign-up: %d %s", rec.Code, rec.Body.String())
	}
	if !permits("someone@example.com") || permits("someone@elsewhere.test") {
		t.Error("the rule admits the wrong addresses")
	}
	rec := call(t, s, http.MethodGet, path, testToken, nil)
	var v signupView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if !v.Enabled || v.AnyDomain || len(v.AllowedDomains) != 1 || v.AllowedDomains[0] != "example.com" ||
		!v.RequireVerifiedEmail || v.RequireApproval {
		t.Errorf("the rule reads %+v; an address is proved unless asked otherwise", v)
	}

	if rec := call(t, s, http.MethodPut, path, testToken, map[string]any{"any_domain": true,
		"require_verified_email": false, "require_approval": true}); rec.Code != http.StatusOK {
		t.Fatalf("opening sign-up to any address: %d %s", rec.Code, rec.Body.String())
	}
	rule, err := store.LoadSignupRule(ctx, s.db, org)
	if err != nil || !rule.Permits("someone@elsewhere.test") || rule.RequireVerify || !rule.RequireApproval {
		t.Errorf("after any_domain the rule is %+v (%v)", rule, err)
	}

	if rec := call(t, s, http.MethodDelete, path, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("closing sign-up: %d %s", rec.Code, rec.Body.String())
	}
	if permits("someone@elsewhere.test") {
		t.Error("closed sign-up still admits an address")
	}
	if rec := call(t, s, http.MethodDelete, path, testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("closing closed sign-up answered %d", rec.Code)
	}
}
