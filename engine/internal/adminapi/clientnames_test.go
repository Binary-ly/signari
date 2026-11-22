package adminapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

// A client's names in other languages through the Admin API (10.12): replaced by PATCH,
// read on the client's own record, refused when they cannot be stored, cleared by {}.
func TestAClientIsNamedInOtherLanguagesThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	clientID := newPreconditionClient(t, s)
	tok := mintToken(t, s, "client names", "", []string{ScopeClientsRead, ScopeClientsWrite}, nil)
	path := "/admin/clients/" + clientID

	names := func() map[string]any {
		t.Helper()
		rec := call(t, s, http.MethodGet, path, tok, nil)
		var c map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("reading the client: %d %s", rec.Code, rec.Body.String())
		}
		got, _ := c["localized_names"].(map[string]any)
		return got
	}
	if got := names(); len(got) != 0 {
		t.Fatalf("a new client already has names %v", got)
	}
	if rec := call(t, s, http.MethodPatch, path, tok, map[string]any{
		"localized_names": map[string]string{"ja": "日本語の名前", "pt-BR": "Nome"},
	}); rec.Code != http.StatusOK {
		t.Fatalf("naming it: %d %s", rec.Code, rec.Body.String())
	}
	if got := names(); got["ja"] != "日本語の名前" || got["pt-BR"] != "Nome" || len(got) != 2 {
		t.Errorf("read back %v", got)
	}
	for _, bad := range []map[string]string{{"not a tag": "x"}, {"de": "   "}, {"de": "a", "DE": "b"}} {
		rec := call(t, s, http.MethodPatch, path, tok, map[string]any{"localized_names": bad})
		var out map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusBadRequest || out["error"] != "invalid_client_name" {
			t.Errorf("%v: %d %s, want 400 invalid_client_name", bad, rec.Code, rec.Body.String())
		}
	}
	if got := names(); len(got) != 2 {
		t.Errorf("a refused change changed the names to %v", got)
	}
	if rec := call(t, s, http.MethodPatch, path, tok, map[string]any{"enabled": true}); rec.Code != http.StatusOK ||
		len(names()) != 2 {
		t.Errorf("a PATCH saying nothing of names took them away: %d", rec.Code)
	}
	if rec := call(t, s, http.MethodPatch, path, tok, map[string]any{"localized_names": map[string]string{}}); rec.Code != http.StatusOK ||
		len(names()) != 0 {
		t.Errorf("{} left %v", names())
	}
}
