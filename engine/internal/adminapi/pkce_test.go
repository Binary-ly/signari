package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// A client made through this API required PKCE only when public: the insert
// bound `require_pkce` to `public`, so every confidential client created
// through the API, the console or Terraform accepted an authorization request
// with no challenge.
func TestAnAPICreatedClientRequiresPKCEUnlessItOptsOut(t *testing.T) {
	s, _ := newTestServer(t)
	org := anyOrgID(t, s)

	stored := func(id string) (bool, bool) {
		t.Helper()
		var pkce, enabled bool
		if err := s.db.QueryRow(context.Background(),
			`SELECT require_pkce, enabled FROM core.clients WHERE client_id = $1`, id).Scan(&pkce, &enabled); err != nil {
			t.Fatalf("reading %s: %v", id, err)
		}
		return pkce, enabled
	}
	create := func(body map[string]any) (string, int, string) {
		t.Helper()
		id := fmt.Sprintf("pkce-%d", time.Now().UnixNano())
		body["client_id"], body["org_id"] = id, org
		body["redirect_uris"] = []string{"https://app.example.test/cb"}
		t.Cleanup(func() {
			_, _ = s.db.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
		})
		rec := call(t, s, http.MethodPost, "/admin/clients", testToken, body)
		return id, rec.Code, rec.Body.String()
	}

	id, code, body := create(map[string]any{})
	if code != http.StatusCreated {
		t.Fatalf("creating a confidential client gave %d %s", code, body)
	}
	if pkce, _ := stored(id); !pkce {
		t.Fatal("a confidential client created with no require_pkce does not require PKCE")
	}

	optedOut, code, body := create(map[string]any{"require_pkce": false})
	if code != http.StatusCreated {
		t.Fatalf("the explicit opt-out gave %d %s", code, body)
	}
	if pkce, _ := stored(optedOut); pkce {
		t.Fatal("require_pkce: false was not stored")
	}

	if _, code, body := create(map[string]any{"public": true, "require_pkce": false}); code != http.StatusBadRequest {
		t.Fatalf("a public client opting out of PKCE gave %d %s, want 400", code, body)
	}

	// PATCH is the opt-out for an existing client, and changes only what it names.
	rec := call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken, map[string]any{"require_pkce": false})
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH require_pkce gave %d %s", rec.Code, rec.Body.String())
	}
	if pkce, enabled := stored(id); pkce || !enabled {
		t.Fatalf("after PATCH require_pkce=false: require_pkce %v, enabled %v", pkce, enabled)
	}
	rec = call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken, map[string]any{"enabled": false})
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH enabled gave %d %s", rec.Code, rec.Body.String())
	}
	if pkce, enabled := stored(id); pkce || enabled {
		t.Fatalf("PATCH enabled=false also changed require_pkce: require_pkce %v, enabled %v", pkce, enabled)
	}

	public, code, body := create(map[string]any{"public": true})
	if code != http.StatusCreated {
		t.Fatalf("creating a public client gave %d %s", code, body)
	}
	rec = call(t, s, http.MethodPatch, "/admin/clients/"+public, testToken, map[string]any{"require_pkce": false})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PATCH a public client out of PKCE gave %d %s, want 400", rec.Code, rec.Body.String())
	}
	if pkce, _ := stored(public); !pkce {
		t.Fatal("the refused PATCH still dropped PKCE on a public client")
	}
}
