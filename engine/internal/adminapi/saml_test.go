package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// newDriftSAMLProvider is an organisation of the test's own with a service
// provider, a declared attribute named department and a group named
// drift-group, and the provider's path.
func newDriftSAMLProvider(t *testing.T, s *Server) (org, path string) {
	t.Helper()
	ctx := context.Background()
	org = newDriftMigrationOrg(t, s, false)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id, err := store.AddSAMLProvider(ctx, tx, org, store.SAMLProviderSpec{EntityID: "https://sp-" + org + ".example.test",
		ACSURL: "https://sp.example.test/acs"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.user_attribute_schema (org_id, name) VALUES ($1::uuid, 'department')`,
		org); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name) VALUES ($1::uuid, 'drift-group', 'Drift')`,
		org); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return org, "/admin/organizations/" + org + "/saml-providers/" + id
}

// A SAML service provider is registered, its signing chosen and its releases
// set and withdrawn through the Admin API as `signari saml` does it (6.07):
// an ACS URL checked as a redirect is, nothing left unsigned, and a release
// naming nothing the organisation has refused.
func TestASAMLProviderIsConfiguredThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	org, provider := newDriftSAMLProvider(t, s)
	base := "/admin/organizations/" + org + "/saml-providers"
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
	entity := "https://wiki-" + org + ".example.test"
	for _, bad := range []map[string]any{
		{"entity_id": entity, "acs_url": "http://wiki.example.test/acs"},
		{"entity_id": entity, "acs_url": "https://*.example.test/acs"},
		{"entity_id": entity, "acs_url": "https://wiki.example.test/acs", "slo_url": "https://wiki.example.test/slo"},
		{"entity_id": entity, "acs_url": "https://wiki.example.test/acs", "want_signed_requests": true},
		{"entity_id": entity, "acs_url": "https://wiki.example.test/acs", "signing_cert": "not a certificate"},
	} {
		if e := errorOf(http.MethodPost, base, bad, http.StatusBadRequest); e != "invalid_saml_provider" {
			t.Errorf("%v answered %q", bad, e)
		}
	}
	if rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"entity_id": entity,
		"acs_url": "https://wiki.example.test/acs", "name_id_format": "emailAddress"}); rec.Code != http.StatusCreated {
		t.Fatalf("registering: %d %s", rec.Code, rec.Body.String())
	}
	// Entity ids are unique across organisations.
	other := "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/saml-providers"
	if e := errorOf(http.MethodPost, other, map[string]any{"entity_id": entity, "acs_url": "https://x.example.test/acs"},
		http.StatusConflict); e != "already_exists" {
		t.Errorf("a second registration of the entity id answered %q", e)
	}

	if e := errorOf(http.MethodPatch, provider, map[string]any{"sign_assertions": false}, http.StatusBadRequest); e != "invalid_saml_provider" {
		t.Errorf("signing nothing answered %q", e)
	}
	if e := errorOf(http.MethodPatch, provider, map[string]any{"lifetime_s": 7200}, http.StatusBadRequest); e != "invalid_saml_provider" {
		t.Errorf("a two-hour assertion answered %q", e)
	}
	if rec := call(t, s, http.MethodPatch, provider, testToken, map[string]any{"sign_responses": true,
		"lifetime_s": 120}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"sign_responses":true`) {
		t.Fatalf("signing responses: %d %s", rec.Code, rec.Body.String())
	}
	// Changing the lifetime alone leaves response signing on.
	if rec := call(t, s, http.MethodPatch, provider, testToken, map[string]any{"lifetime_s": 90}); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"sign_responses":true`) {
		t.Errorf("changing only the lifetime: %d %s", rec.Code, rec.Body.String())
	}

	release := provider + "/attribute-release"
	const claim = "http://schemas.xmlsoap.org/claims/Department"
	if e := errorOf(http.MethodPut, release, map[string]string{"saml_attribute": claim, "attribute": "cost_centre"},
		http.StatusBadRequest); e != "invalid_saml_provider" {
		t.Errorf("releasing an undeclared attribute answered %q", e)
	}
	if rec := call(t, s, http.MethodPut, release, testToken, map[string]string{"saml_attribute": claim,
		"attribute": "department"}); rec.Code != http.StatusOK {
		t.Fatalf("releasing: %d %s", rec.Code, rec.Body.String())
	}
	groups := provider + "/group-release"
	if e := errorOf(http.MethodPut, groups, map[string]any{"only": []string{"nobody"}}, http.StatusBadRequest); e != "invalid_saml_provider" {
		t.Errorf("releasing a group the organisation lacks answered %q", e)
	}
	if rec := call(t, s, http.MethodPut, groups, testToken, map[string]any{"only": []string{"drift-group"}}); rec.Code != http.StatusOK {
		t.Fatalf("releasing groups: %d %s", rec.Code, rec.Body.String())
	}
	list := call(t, s, http.MethodGet, base, testToken, nil)
	if !strings.Contains(list.Body.String(), `"attribute_release":{"`+claim+`":"department"}`) ||
		!strings.Contains(list.Body.String(), `"group_release":{"attribute_name":"groups","only":["drift-group"]}`) {
		t.Errorf("the providers read %s", list.Body.String())
	}

	withdraw := release + "?saml_attribute=" + url.QueryEscape(claim)
	if rec := call(t, s, http.MethodDelete, withdraw, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("withdrawing: %d %s", rec.Code, rec.Body.String())
	}
	if e := errorOf(http.MethodDelete, withdraw, nil, http.StatusNotFound); e != "release_not_found" {
		t.Errorf("withdrawing it again answered %q", e)
	}
	if rec := call(t, s, http.MethodDelete, groups, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("stopping the group release: %d", rec.Code)
	}
	if e := errorOf(http.MethodDelete, groups, nil, http.StatusNotFound); e != "release_not_found" {
		t.Errorf("stopping it again answered %q", e)
	}
	// Another organisation's provider is not this one's.
	_, theirs := newDriftSAMLProvider(t, s)
	mine := "/admin/organizations/" + org + "/saml-providers/" + theirs[strings.LastIndex(theirs, "/")+1:]
	if e := errorOf(http.MethodPatch, mine, map[string]any{"lifetime_s": 60}, http.StatusNotFound); e != "provider_not_found" {
		t.Errorf("another organisation's provider answered %q", e)
	}
}
