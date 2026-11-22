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
	// Nor a back channel a logout token cannot safely be posted to, which was
	// stored unchecked (6.03).
	for _, bcl := range []string{"http://rp.test/bcl", "https://rp.test/bcl#f"} {
		if code, out := register(`{"redirect_uris":["https://rp.test/cb"],"backchannel_logout_uri":"` + bcl + `"}`); code != http.StatusBadRequest ||
			out["error"] != "invalid_client_metadata" {
			t.Errorf("a back-channel logout URI %s registered: %d %v", bcl, code, out)
			if id, _ := out["client_id"].(string); id != "" {
				_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
			}
		}
	}

	// The signing algorithm is echoed whether or not it was asked for, and one
	// the instance cannot sign with is refused rather than answered in another
	// (2.23). This fixture's instance holds no stored keys at all.
	if out["id_token_signed_response_alg"] != "ES256" {
		t.Errorf("the response gives the signing algorithm as %v, want the default ES256",
			out["id_token_signed_response_alg"])
	}
	// A client may require PAR of itself (RFC 9126 §6), and is told it did.
	code, par := register(`{"redirect_uris":["https://rp.test/cb"],"require_pushed_authorization_requests":true}`)
	parID, _ := par["client_id"].(string)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, parID)
	})
	if st, err := store.ClientSettingsOf(context.Background(), f.pool, parID); code != http.StatusCreated ||
		par["require_pushed_authorization_requests"] != true || err != nil || !st.RequirePAR {
		t.Errorf("registering require_pushed_authorization_requests gave %d %v, stored %v (%v)",
			code, par["require_pushed_authorization_requests"], st.RequirePAR, err)
	}

	for _, alg := range []string{"HS256", "RS256"} {
		if code, out := register(`{"redirect_uris":["https://rp.test/cb"],
			"id_token_signed_response_alg":"` + alg + `"}`); code != http.StatusBadRequest ||
			out["error"] != "invalid_client_metadata" {
			t.Errorf("%s registered: %d %v", alg, code, out)
		}
	}
}
