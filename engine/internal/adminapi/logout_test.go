package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// The client PATCH registers sign-out through the same writer as the CLI,
// `apply` and dynamic registration, changing only the fields it names (2.11).
func TestAClientPATCHRegistersSignOut(t *testing.T) {
	s, _ := newTestServer(t)
	org := anyOrgID(t, s)
	id := fmt.Sprintf("logout-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
	})
	if rec := call(t, s, http.MethodPost, "/admin/clients", testToken, map[string]any{
		"client_id": id, "org_id": org, "redirect_uris": []string{"https://app.example.test/cb"},
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create gave %d %s", rec.Code, rec.Body.String())
	}

	rec := call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken, map[string]any{
		"post_logout_redirect_uris": []string{"https://app.example.test/bye"},
		"frontchannel_logout_uri":   "https://app.example.test/fc",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH gave %d %s", rec.Code, rec.Body.String())
	}
	uris, fc, sid, err := store.ClientLogoutOf(context.Background(), s.db, id)
	if err != nil || len(uris) != 1 || fc != "https://app.example.test/fc" || !sid {
		t.Errorf("stored %q %q %v (%v); the session flag keeps its default, true", uris, fc, sid, err)
	}
	// The session flag alone leaves the URIs as they are.
	rec = call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken,
		map[string]any{"frontchannel_logout_session_required": false})
	if uris, fc, sid, _ := store.ClientLogoutOf(context.Background(), s.db, id); rec.Code != http.StatusOK ||
		len(uris) != 1 || fc == "" || sid {
		t.Errorf("the flag alone gave %d and left %q %q %v", rec.Code, uris, fc, sid)
	}
	if rec := call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken,
		map[string]any{"frontchannel_logout_uri": "https://app.example.test/fc#frag"}); rec.Code != http.StatusBadRequest {
		t.Errorf("a front-channel URI with a fragment gave %d", rec.Code)
	}
}
