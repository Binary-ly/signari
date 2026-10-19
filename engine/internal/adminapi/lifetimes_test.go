package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// The client PATCH sets token lifetimes through the same writer as `client
// set-lifetimes` and `apply`, changing only the one it names (2.23).
func TestAClientPATCHSetsTokenLifetimes(t *testing.T) {
	s, _ := newTestServer(t)
	org := anyOrgID(t, s)
	id := fmt.Sprintf("lifetimes-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
	})
	if rec := call(t, s, http.MethodPost, "/admin/clients", testToken, map[string]any{
		"client_id": id, "org_id": org, "redirect_uris": []string{"https://app.example.test/cb"},
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create gave %d %s", rec.Code, rec.Body.String())
	}

	rec := call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken,
		map[string]any{"access_token_ttl_s": 900})
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH gave %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["access_token_ttl_s"] != float64(900) || out["refresh_token_ttl_s"] != float64(2592000) {
		t.Errorf("the response gave %v and %v, want 900 and the untouched default",
			out["access_token_ttl_s"], out["refresh_token_ttl_s"])
	}
	got, err := store.ClientSettingsOf(context.Background(), s.db, id)
	if err != nil || got.AccessTokenTTL != 15*time.Minute || got.RefreshTokenTTL != 30*24*time.Hour {
		t.Errorf("stored %v / %v (%v)", got.AccessTokenTTL, got.RefreshTokenTTL, err)
	}

	for _, body := range []map[string]any{
		{"access_token_ttl_s": 30}, {"access_token_ttl_s": 7200}, {"refresh_token_ttl_s": 60},
	} {
		rec := call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken, body)
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusBadRequest || out["error"] != "invalid_client_setting" {
			t.Errorf("%v gave %d %v", body, rec.Code, out["error"])
		}
	}
}
