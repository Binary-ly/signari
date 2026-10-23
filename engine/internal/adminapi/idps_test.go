package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// newDriftIdP is an organisation of the test's own with a sign-in provider of
// that kind and a declared attribute named department, and the provider's
// path. A slug is unique across the deployment, so it carries the
// organisation's id.
func newDriftIdP(t *testing.T, s *Server, kind string) (org, slug, path string) {
	t.Helper()
	ctx := context.Background()
	org = newDriftMigrationOrg(t, s, false)
	slug = "drift-" + org[:8]
	if _, err := s.db.Exec(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, scopes)
		VALUES ($1::uuid, $2, 'Drift', $3, 'drift-client', '{openid}')`, org, slug, kind); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO core.user_attribute_schema (org_id, name) VALUES ($1::uuid, 'department')`,
		org); err != nil {
		t.Fatal(err)
	}
	return org, slug, "/admin/organizations/" + org + "/identity-providers/" + slug
}

// An upstream provider is taken out of service, allowed its assertions,
// trusted for multi-factor and given an attribute mapping through the Admin
// API as `signari idp` does it (6.07).
func TestAnIdentityProviderIsConfiguredThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org, slug, path := newDriftIdP(t, s, "oidc")
	errorOf := func(method, p string, body any, want int) string {
		t.Helper()
		rec := call(t, s, method, p, testToken, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Errorf("%s %s %v answered %d, want %d: %s", method, p, body, rec.Code, want, rec.Body.String())
		}
		e, _ := out["error"].(string)
		return e
	}
	read := func() (enabled, assertions, trusts, requires bool, amr []string) {
		t.Helper()
		if err := s.db.QueryRow(ctx, `SELECT enabled, allow_jwt_bearer, trust_email_verification, require_verified_email,
			mfa_amr FROM core.identity_providers WHERE slug = $1`, slug).Scan(&enabled, &assertions, &trusts, &requires,
			&amr); err != nil {
			t.Fatal(err)
		}
		return
	}
	if rec := call(t, s, http.MethodPatch, path, testToken, map[string]any{"enabled": false, "allow_assertions": true,
		"trust_email_verification": true, "require_verified_email": false,
		"mfa_amr": []string{"mfa", " otp "}}); rec.Code != http.StatusOK {
		t.Fatalf("changing the provider: %d %s", rec.Code, rec.Body.String())
	}
	if enabled, assertions, trusts, requires, amr := read(); enabled || !assertions || !trusts || requires ||
		strings.Join(amr, ",") != "mfa,otp" {
		t.Errorf("the provider reads enabled %v, assertions %v, trusts %v, requires %v, amr %v",
			enabled, assertions, trusts, requires, amr)
	}
	// One change keeps the others.
	if rec := call(t, s, http.MethodPatch, path, testToken, map[string]any{"enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("enabling: %d", rec.Code)
	}
	if enabled, assertions, trusts, requires, amr := read(); !enabled || !assertions || !trusts || requires ||
		len(amr) != 2 {
		t.Errorf("enabling alone left assertions %v, trusts %v, requires %v, amr %v", assertions, trusts, requires, amr)
	}
	if e := errorOf(http.MethodPatch, path, map[string]any{}, http.StatusBadRequest); e != "nothing_to_change" {
		t.Errorf("an empty change answered %q", e)
	}
	if e := errorOf(http.MethodPatch, "/admin/organizations/"+org+"/identity-providers/elsewhere",
		map[string]any{"enabled": false}, http.StatusNotFound); e != "provider_not_found" {
		t.Errorf("an unknown provider answered %q", e)
	}
	// Another organisation's provider is not this one's.
	_, theirs, _ := newDriftIdP(t, s, "google")
	if e := errorOf(http.MethodPatch, "/admin/organizations/"+org+"/identity-providers/"+theirs,
		map[string]any{"enabled": false}, http.StatusNotFound); e != "provider_not_found" {
		t.Errorf("another organisation's provider answered %q", e)
	}

	maps := path + "/attribute-map"
	if e := errorOf(http.MethodPut, maps, map[string]any{"claim": "dept", "attribute": "cost_centre"},
		http.StatusBadRequest); e != "invalid_identity_provider" {
		t.Errorf("an undeclared attribute answered %q", e)
	}
	if rec := call(t, s, http.MethodPut, maps, testToken, map[string]any{"claim": "dept", "attribute": "department",
		"overwrite": true}); rec.Code != http.StatusOK {
		t.Fatalf("mapping: %d %s", rec.Code, rec.Body.String())
	}
	list := call(t, s, http.MethodGet, "/admin/organizations/"+org+"/identity-providers", testToken, nil)
	if !strings.Contains(list.Body.String(), `"attribute":"department","claim":"dept","max_length":256,"overwrite":true`) {
		t.Errorf("the providers read %s", list.Body.String())
	}
	unmap := maps + "?claim=dept&attribute=department"
	if rec := call(t, s, http.MethodDelete, unmap, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("unmapping: %d %s", rec.Code, rec.Body.String())
	}
	if e := errorOf(http.MethodDelete, unmap, nil, http.StatusNotFound); e != "mapping_not_found" {
		t.Errorf("unmapping it again answered %q", e)
	}

	// A provider that sends no ID token has nothing to read amr from, and a
	// named provider's belief in email_verified is its preset's: either set
	// here would be read by nothing.
	ghOrg, ghSlug, gh := newDriftIdP(t, s, "github")
	if e := errorOf(http.MethodPatch, gh, map[string]any{"mfa_amr": []string{"mfa"}},
		http.StatusBadRequest); e != "invalid_identity_provider" {
		t.Errorf("multi-factor values on a GitHub provider answered %q", e)
	}
	if e := errorOf(http.MethodPatch, gh, map[string]any{"trust_email_verification": true},
		http.StatusBadRequest); e != "invalid_identity_provider" {
		t.Errorf("belief in a GitHub provider's email_verified answered %q", e)
	}
	if err := store.ChangeIdentityProvider(ctx, s.db, ghOrg, ghSlug,
		store.IdentityProviderChange{RequireVerifiedEmail: new(bool)}); err != nil {
		t.Errorf("a GitHub provider's sign-ups: %v", err)
	}
}

// A token narrowed to some applications cannot change how the whole
// organisation signs in through a provider.
func TestANarrowedTokenCannotChangeAnIdentityProvider(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org, slug, path := newDriftIdP(t, s, "oidc")
	client := clientIn(t, s, org)
	narrowed, _, err := NewToken(ctx, s.db, "idp-narrowed-"+client, org,
		[]string{ScopeOrganizationsWrite}, nil, []string{client}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE token_hash = $1`, sha256Of(narrowed))
	})
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPatch, path, map[string]any{"trust_email_verification": true}},
		{http.MethodPut, path + "/attribute-map", map[string]any{"claim": "dept", "attribute": "department"}},
	} {
		rec := call(t, s, c.method, c.path, narrowed, c.body)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "outside_token_objects") {
			t.Errorf("a narrowed token's %s %s answered %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	var trusts bool
	if err := s.db.QueryRow(ctx, `SELECT trust_email_verification FROM core.identity_providers WHERE slug = $1`,
		slug).Scan(&trusts); err != nil || trusts {
		t.Errorf("after the refusal the provider trusts %v (%v)", trusts, err)
	}
}
