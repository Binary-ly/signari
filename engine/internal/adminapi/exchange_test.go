package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Token exchange is granted through the client PATCH, by the same writer as
// the CLI and `signari apply`, and only what the request names changes.
func TestAClientPATCHGrantsAndWithdrawsTokenExchange(t *testing.T) {
	s, _ := newTestServer(t)
	org := anyOrgID(t, s)
	create := func(public bool) string {
		t.Helper()
		id := fmt.Sprintf("exch-%d", time.Now().UnixNano())
		t.Cleanup(func() {
			_, _ = s.db.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
		})
		rec := call(t, s, http.MethodPost, "/admin/clients", testToken, map[string]any{
			"client_id": id, "org_id": org, "public": public,
			"redirect_uris": []string{"https://app.example.test/cb"},
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("creating a client gave %d %s", rec.Code, rec.Body.String())
		}
		return id
	}
	stored := func(id string) (bool, []string, bool) {
		t.Helper()
		var may, enabled bool
		var aud []string
		if err := s.db.QueryRow(context.Background(),
			`SELECT may_exchange, exchange_audiences, enabled FROM core.clients WHERE client_id = $1`, id).
			Scan(&may, &aud, &enabled); err != nil {
			t.Fatal(err)
		}
		return may, aud, enabled
	}

	id := create(false)
	rec := call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken, map[string]any{
		"may_exchange": true, "exchange_audiences": []string{"https://billing.test/api", " https://billing.test/api "},
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"may_exchange":true`) {
		t.Fatalf("granting exchange gave %d %s", rec.Code, rec.Body.String())
	}
	if may, aud, enabled := stored(id); !may || len(aud) != 1 || aud[0] != "https://billing.test/api" || !enabled {
		t.Fatalf("stored may_exchange %v audiences %q enabled %v", may, aud, enabled)
	}

	// Audiences alone keep the permission; the permission alone keeps nothing
	// it withdrew.
	rec = call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken, map[string]any{
		"exchange_audiences": []string{"https://ledger.test/api"},
	})
	if may, aud, _ := stored(id); rec.Code != http.StatusOK || !may || len(aud) != 1 || aud[0] != "https://ledger.test/api" {
		t.Errorf("replacing the audiences gave %d, stored %v %q", rec.Code, may, aud)
	}
	rec = call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken, map[string]any{"may_exchange": false})
	if may, aud, _ := stored(id); rec.Code != http.StatusOK || may || len(aud) != 0 {
		t.Errorf("withdrawing gave %d, stored %v %q", rec.Code, may, aud)
	}

	for name, body := range map[string]map[string]any{
		"an audience with a space": {"may_exchange": true, "exchange_audiences": []string{"two words"}},
	} {
		if rec := call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken, body); rec.Code != http.StatusBadRequest ||
			!strings.Contains(rec.Body.String(), "invalid_audience") {
			t.Errorf("%s gave %d %s", name, rec.Code, rec.Body.String())
		}
	}
	public := create(true)
	if rec := call(t, s, http.MethodPatch, "/admin/clients/"+public, testToken, map[string]any{"may_exchange": true}); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "confidential_client_required") {
		t.Errorf("granting a public client gave %d %s", rec.Code, rec.Body.String())
	}
	if may, _, _ := stored(public); may {
		t.Error("the refused grant was stored")
	}
}
