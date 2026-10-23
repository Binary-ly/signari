package adminapi

import (
	"context"
	"net/http"
	"testing"
)

// A mapper releasing an attribute to every client is one mapper, as a mapper
// for one client is (0.39). 0113's UNIQUE took a NULL client id as distinct
// from every other, so declaring the all-clients mapper again under a new claim
// name added a second one: the attribute went on being released under the
// name an operator meant to retire, beside the new one.
func TestAnAllClientsMapperDeclaredAgainIsReplaced(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	if _, err := s.db.Exec(ctx, `INSERT INTO core.user_attribute_schema (org_id, name) VALUES ($1::uuid, 'cost_centre')`,
		org); err != nil {
		t.Fatal(err)
	}
	path := "/admin/organizations/" + org + "/claim-mappers"
	for _, claim := range []string{"cost_centre", "https://example.test/cost_centre"} {
		if rec := call(t, s, http.MethodPost, path, testToken, map[string]any{"attribute": "cost_centre",
			"claim_name": claim, "destination": "id_token", "all_clients": true}); rec.Code != http.StatusOK {
			t.Fatalf("declaring the mapper as %s: %d %s", claim, rec.Code, rec.Body.String())
		}
	}
	var n int
	var claim string
	if err := s.db.QueryRow(ctx, `SELECT count(*), max(claim_name) FROM core.claim_mappers
		WHERE org_id = $1::uuid AND client_id IS NULL`, org).Scan(&n, &claim); err != nil {
		t.Fatal(err)
	}
	if n != 1 || claim != "https://example.test/cost_centre" {
		t.Errorf("the organisation releases cost_centre to every client through %d mapper(s), the last as %q; "+
			"want one, as the new name", n, claim)
	}
}
