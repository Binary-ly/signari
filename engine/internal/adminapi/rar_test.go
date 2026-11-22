package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// clientIn is a client of the given organisation.
func clientIn(t *testing.T, s *Server, orgID string) string {
	t.Helper()
	id := fmt.Sprintf("in-%d", time.Now().UnixNano())
	if _, err := s.db.Exec(context.Background(), `INSERT INTO core.clients (client_id, org_id, display_name,
		client_type, client_secret_hash, enabled) VALUES ($1, $2::uuid, 'fixture', 'confidential', 'x', true)`,
		id, orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.db.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id) })
	return id
}

// Authorization details types are registered and granted to clients through
// the Admin API as `signari rar` does it (6.07), and what is written is what the
// authorization endpoint reads. A type of the same name in two organisations is
// each organisation's own: the command found it in whichever came back first,
// and refused the other's client as belonging elsewhere (0.32).
func TestAuthorizationDetailsTypesAreRegisteredAndGrantedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	orgA, orgB := newDriftMigrationOrg(t, s, false), newDriftMigrationOrg(t, s, false)
	clientB := clientIn(t, s, orgB)
	put := func(org string, body map[string]any) int {
		t.Helper()
		return call(t, s, http.MethodPut, "/admin/organizations/"+org+"/authorization-detail-types", testToken, body).Code
	}
	for _, bad := range []map[string]any{
		{"type": "payment"},
		{"type": "payment", "fields": []string{"amount"}},
		{"type": "payment", "fields": []string{"actions"}, "required": []string{"locations"}},
		{"fields": []string{"actions"}},
	} {
		if code := put(orgB, bad); code != http.StatusBadRequest {
			t.Errorf("%v answered %d", bad, code)
		}
	}
	for _, org := range []string{orgA, orgB} {
		if code := put(org, map[string]any{"type": "payment", "fields": []string{"actions", "locations"},
			"required": []string{"actions"}}); code != http.StatusOK {
			t.Fatalf("registering the type in %s: %d", org, code)
		}
	}

	patch := func(types []string) (int, map[string]any) {
		t.Helper()
		rec := call(t, s, http.MethodPatch, "/admin/clients/"+clientB, testToken, map[string]any{
			"authorization_detail_types": types})
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	if code, out := patch([]string{"payment", "unregistered"}); code != http.StatusBadRequest ||
		out["error"] != "invalid_authorization_details_type" {
		t.Errorf("granting a type the organisation never registered answered %d %v", code, out)
	}
	if code, out := patch([]string{"payment"}); code != http.StatusOK {
		t.Fatalf("granting the type: %d %v", code, out)
	}
	registry, err := store.AuthorizationDetailTypes(ctx, s.db, orgB, clientB)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := registry["payment"]; !ok {
		t.Errorf("the authorization endpoint's registry for the client is %v", registry)
	}
	rec := call(t, s, http.MethodGet, "/admin/clients/"+clientB, testToken, nil)
	var c map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &c)
	if got, _ := c["authorization_detail_types"].([]any); len(got) != 1 || got[0] != "payment" {
		t.Errorf("the client reads authorization_detail_types %v", c["authorization_detail_types"])
	}

	listed := func(org string) []string {
		t.Helper()
		rec := call(t, s, http.MethodGet, "/admin/organizations/"+org+"/authorization-detail-types", testToken, nil)
		var out struct {
			Types []detailTypeView `json:"authorization_detail_types"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Types) != 1 {
			t.Fatalf("%s lists %+v", org, out.Types)
		}
		return out.Types[0].Clients
	}
	if got := listed(orgA); len(got) != 0 {
		t.Errorf("the other organisation's type lists %v as its clients", got)
	}
	if got := listed(orgB); !slices.Equal(got, []string{clientB}) {
		t.Errorf("the organisation's type lists %v", got)
	}

	// The command's path: the type found in the client's own organisation.
	if _, err := s.db.Exec(ctx, `DELETE FROM core.client_authorization_detail_types WHERE client_id = $1`, clientB); err != nil {
		t.Fatal(err)
	}
	if err := store.AllowClientDetailType(ctx, s.db, clientB, "payment"); err != nil {
		t.Errorf("allowing a type both organisations registered, for the second's client: %v", err)
	}

	if rec := call(t, s, http.MethodDelete, "/admin/organizations/"+orgB+"/authorization-detail-types?type=payment",
		testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("forgetting the type: %d %s", rec.Code, rec.Body.String())
	}
	if got, _ := store.ClientDetailTypes(ctx, s.db, clientB); len(got) != 0 {
		t.Errorf("a forgotten type is still granted to %v", got)
	}
}
