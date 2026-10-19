package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// A dynamically registered client's sign-out metadata is stored and echoed,
// and a URI that would be refused at sign-out is refused here instead. Both
// were dropped as unmodelled metadata (2.11).
func TestDynamicRegistrationRecordsTheSignOutMetadata(t *testing.T) {
	f := newTokenFixture(t)
	register := func(body string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/oauth2/register", strings.NewReader(body))
		req.RemoteAddr = freshAddress() + ":443"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+registrationToken(t, f))
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	code, out := register(`{"redirect_uris":["https://rp.test/cb"],
		"post_logout_redirect_uris":["https://rp.test/bye"],
		"frontchannel_logout_uri":"https://rp.test/fc","frontchannel_logout_session_required":true}`)
	if code != http.StatusCreated {
		t.Fatalf("registration answered %d %v", code, out)
	}
	id, _ := out["client_id"].(string)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
	})
	if out["frontchannel_logout_uri"] != "https://rp.test/fc" || out["post_logout_redirect_uris"] == nil {
		t.Errorf("the response does not echo the sign-out metadata: %v", out)
	}
	uris, fc, sid, err := store.ClientLogoutOf(context.Background(), f.pool, id)
	if err != nil || len(uris) != 1 || uris[0] != "https://rp.test/bye" || fc != "https://rp.test/fc" || !sid {
		t.Errorf("stored %q %q %v (%v)", uris, fc, sid, err)
	}

	if code, out := register(`{"redirect_uris":["https://rp.test/cb"],
		"post_logout_redirect_uris":["http://rp.test/plaintext"]}`); code != http.StatusBadRequest ||
		out["error"] != "invalid_client_metadata" {
		t.Errorf("a plaintext post-logout URI registered: %d %v", code, out)
	}
}
