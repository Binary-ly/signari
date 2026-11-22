package adminapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// newDriftOrg is an organisation of the test's own, so a brand put on it is on
// nobody else's pages.
func newDriftOrg(t *testing.T, s *Server) string {
	t.Helper()
	return newDriftMigrationOrg(t, s, false)
}

// With no flow of its own an organisation is told the built-in journeys, and says
// so; a flow's stages are what a person would walk, in order.
func TestTheJourneysAreTheFlowsOwn(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftOrg(t, s)
	rec := call(t, s, http.MethodGet, "/admin/organizations/"+org+"/sign-in-flow/paths", testToken, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"applied":false`) ||
		!strings.Contains(rec.Body.String(), `"stages":["`) {
		t.Fatalf("the paths answered %d: %.300s", rec.Code, rec.Body)
	}
	other := newDriftOrg(t, s)
	mine := mintToken(t, s, "paths-"+org, org, []string{ScopeConfigRead}, nil)
	if got := call(t, s, http.MethodGet, "/admin/organizations/"+other+"/sign-in-flow/paths", mine, nil); got.Code != http.StatusForbidden {
		t.Errorf("a token of one organisation read another's: %d %s", got.Code, got.Body)
	}
}

func TestAnOrganisationBrandsItself(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org, other := newDriftOrg(t, s), newDriftOrg(t, s)
	path := "/admin/organizations/" + org + "/brand"

	// Contrast holds here too: a tenant's page is read by the same people.
	for _, bad := range []map[string]any{
		{"logo_url": "http://acme.example/logo.png"},
		{"colour_primary": "#123456"},
		{"colour_primary": "#000000", "colour_on_primary": "#ffffff",
			"colour_background": "#777777", "colour_text": "#888888"},
	} {
		rec := call(t, s, http.MethodPut, path, testToken, bad)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_brand") {
			t.Errorf("%v answered %d: %s", bad, rec.Code, rec.Body)
		}
	}
	if b, err := store.OrgBrandOf(ctx, s.db, org); err != nil || b != nil {
		t.Fatalf("a refused brand was stored: %+v, %v", b, err)
	}

	rec := call(t, s, http.MethodPut, path, testToken, map[string]any{"product_name": "Acme",
		"logo_url": "https://acme.example/logo.png", "colour_primary": "#aa0000", "colour_on_primary": "#ffffff",
		"colour_background": "#fafafa", "colour_text": "#101010"})
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") == "" {
		t.Fatalf("setting the brand answered %d: %s", rec.Code, rec.Body)
	}
	read := call(t, s, http.MethodGet, path, testToken, nil)
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"product_name":"Acme"`) ||
		!strings.Contains(read.Body.String(), `"branded":true`) {
		t.Errorf("reading it back answered %d: %s", read.Code, read.Body)
	}

	// Its own appearance is a tenant's own, and nobody else's.
	mine := mintToken(t, s, "brand-"+org, org, []string{ScopeConfigRead, ScopeOrganizationsWrite}, nil)
	if got := call(t, s, http.MethodPut, path, mine, map[string]any{"product_name": "Mine"}); got.Code != http.StatusOK {
		t.Errorf("a token of the organisation answered %d: %s", got.Code, got.Body)
	}
	if got := call(t, s, http.MethodPut, "/admin/organizations/"+other+"/brand", mine,
		map[string]any{"product_name": "Theirs"}); got.Code != http.StatusForbidden {
		t.Errorf("a token of one organisation branded another: %d %s", got.Code, got.Body)
	}
	if got := call(t, s, http.MethodGet, "/admin/organizations/"+other+"/brand", mine, nil); got.Code != http.StatusForbidden {
		t.Errorf("a token of one organisation read another's: %d %s", got.Code, got.Body)
	}

	if got := call(t, s, http.MethodDelete, path, testToken, nil); got.Code != http.StatusOK {
		t.Fatalf("removing it answered %d: %s", got.Code, got.Body)
	}
	if got := call(t, s, http.MethodDelete, path, testToken, nil); got.Code != http.StatusNotFound {
		t.Errorf("removing nothing answered %d: %s", got.Code, got.Body)
	}
	if b, err := store.OrgBrandOf(ctx, s.db, org); err != nil || b != nil {
		t.Errorf("the brand survived: %+v, %v", b, err)
	}
}
