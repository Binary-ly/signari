package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// A hook's provider is registered, bounded, rotated and removed through the
// Admin API as `signari provider` does it (6.07): no default failure mode, its
// secret shown once and kept across a replacement, and no protocol claim in
// what a token hook may add.
func TestAProviderIsManagedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org + "/providers"
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
	for _, bad := range []struct {
		hook string
		body map[string]any
	}{
		{"authorize", map[string]any{"url": "https://policy.example.test/decide"}},
		{"authorize", map[string]any{"url": "http://policy.example.test/decide", "mode": "fail_closed"}},
		{"authorize", map[string]any{"url": "https://10.0.0.1/decide", "mode": "fail_closed"}},
		{"authorize", map[string]any{"url": "https://policy.example.test/decide", "mode": "fail_closed", "timeout_ms": 9000}},
		{"before_login", map[string]any{"url": "https://policy.example.test/decide", "mode": "fail_closed"}},
	} {
		if e := errorOf(http.MethodPut, base+"/"+bad.hook, bad.body, http.StatusBadRequest); e != "invalid_provider" {
			t.Errorf("%s %v answered %q", bad.hook, bad.body, e)
		}
	}
	var count int
	_ = s.db.QueryRow(ctx, `SELECT count(*) FROM core.providers WHERE org_id = $1::uuid`, org).Scan(&count)
	if count != 0 {
		t.Fatalf("a refused registration stored %d providers", count)
	}

	rec := call(t, s, http.MethodPut, base+"/token_issue", testToken,
		map[string]any{"url": "https://claims.example.test/add", "mode": "fail_open"})
	var made struct {
		ID, Secret string
		Called     bool
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &made)
	if rec.Code != http.StatusOK || made.Secret == "" || !made.Called {
		t.Fatalf("registering: %d %s", rec.Code, rec.Body.String())
	}
	var timeoutMS int
	_ = s.db.QueryRow(ctx, `SELECT timeout_ms FROM core.providers WHERE id = $1::uuid`, made.ID).Scan(&timeoutMS)
	if timeoutMS != 2000 {
		t.Errorf("an unstated timeout stored %dms, want the command's 2000", timeoutMS)
	}
	sealed := func() []byte {
		var b []byte
		if err := s.db.QueryRow(ctx, `SELECT token_wrapped FROM core.providers WHERE id = $1::uuid`,
			made.ID).Scan(&b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	first := sealed()
	rec = call(t, s, http.MethodPut, base+"/token_issue", testToken,
		map[string]any{"url": "https://claims.example.test/add", "mode": "fail_open", "timeout_ms": 1500})
	var replaced struct{ Secret string }
	_ = json.Unmarshal(rec.Body.Bytes(), &replaced)
	if rec.Code != http.StatusOK || replaced.Secret != "" || !bytes.Equal(sealed(), first) {
		t.Errorf("a replacement answered %d with a secret %q and kept the stored one: %v", rec.Code,
			replaced.Secret, bytes.Equal(sealed(), first))
	}

	if e := errorOf(http.MethodPut, base+"/token_issue/claims", map[string]any{"claims": []string{"department", "sub"}},
		http.StatusBadRequest); e != "protocol_claim" {
		t.Errorf("a protocol claim answered %q", e)
	}
	if rec := call(t, s, http.MethodPut, base+"/token_issue/claims", testToken,
		map[string]any{"claims": []string{" department ", "department", "cost_centre"}}); rec.Code != http.StatusOK {
		t.Fatalf("bounding the claims: %d %s", rec.Code, rec.Body.String())
	}
	list := call(t, s, http.MethodGet, base, testToken, nil)
	if strings.Contains(list.Body.String(), made.Secret) ||
		!strings.Contains(list.Body.String(), `"allowed_claims":["department","cost_centre"]`) ||
		!strings.Contains(list.Body.String(), `"timeout_ms":1500`) {
		t.Errorf("the providers read %s", list.Body.String())
	}
	if e := errorOf(http.MethodPut, base+"/authorize/claims", map[string]any{"claims": []string{"x"}},
		http.StatusNotFound); e != "provider_not_found" {
		t.Errorf("claims for an unregistered hook answered %q", e)
	}

	rec = call(t, s, http.MethodPost, base+"/token_issue/rotate-secret", testToken, nil)
	var rotated struct{ Secret string }
	_ = json.Unmarshal(rec.Body.Bytes(), &rotated)
	if rec.Code != http.StatusOK || rotated.Secret == "" || rotated.Secret == made.Secret || bytes.Equal(sealed(), first) {
		t.Errorf("rotating answered %d and the stored secret moved: %v", rec.Code, !bytes.Equal(sealed(), first))
	}

	if rec := call(t, s, http.MethodDelete, base+"/token_issue", testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("removing: %d", rec.Code)
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodDelete, base + "/token_issue"},
		{http.MethodPost, base + "/token_issue/rotate-secret"},
		{http.MethodPost, base + "/before_login/rotate-secret"},
	} {
		if e := errorOf(c.method, c.path, nil, http.StatusNotFound); e != "provider_not_found" {
			t.Errorf("%s %s answered %q", c.method, c.path, e)
		}
	}
}

// A token narrowed to one application cannot register a provider, which is
// consulted on every application's sign-ins.
func TestANarrowedTokenCannotRegisterAProvider(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	client := clientIn(t, s, org)
	narrowed, _, err := NewToken(ctx, s.db, "provider-narrowed-"+client, org,
		[]string{ScopeOrganizationsWrite}, nil, []string{client}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE token_hash = $1`, sha256Of(narrowed))
	})
	rec := call(t, s, http.MethodPut, "/admin/organizations/"+org+"/providers/authorize", narrowed,
		map[string]any{"url": "https://policy.example.test/decide", "mode": "fail_closed"})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "outside_token_objects") {
		t.Errorf("a narrowed token registering answered %d %s", rec.Code, rec.Body.String())
	}
	var count int
	_ = s.db.QueryRow(ctx, `SELECT count(*) FROM core.providers WHERE org_id = $1::uuid`, org).Scan(&count)
	if count != 0 {
		t.Errorf("the refused registration stored %d providers", count)
	}
}
