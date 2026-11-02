package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"signari.dev/engine/internal/keys"
)

// Which servers a client may have a grant for, through the API as `signari client
// id-jag-allow` keeps them.
func TestAClientsGrantAudiencesAreKeptThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	client := newPreconditionClient(t, s)
	path := "/admin/clients/" + url.PathEscape(client) + "/id-jag-audiences"
	audience := "https://as.chat.example/"

	put := func(body map[string]any) *idJAGAnswer {
		t.Helper()
		rec := call(t, s, http.MethodPut, path, testToken, body)
		return &idJAGAnswer{rec.Code, rec.Body.String()}
	}
	for name, body := range map[string]map[string]any{
		"http":                      {"audience": "http://as.chat.example/", "remote_client_id": "x", "alg": "ES256"},
		"no audience":               {"remote_client_id": "x", "alg": "ES256"},
		"no name over there":        {"audience": audience, "alg": "ES256"},
		"an algorithm nobody takes": {"audience": audience, "remote_client_id": "x", "alg": "HS256"},
	} {
		if got := put(body); got.code != http.StatusBadRequest {
			t.Errorf("%s answered %d %s", name, got.code, got.body)
		}
	}
	// What is not held cannot sign, and finding that out at the first request is too late.
	var instanceID string
	if err := s.db.QueryRow(ctx, `SELECT o.instance_id::text FROM core.clients c JOIN core.organizations o ON o.id = c.org_id
		WHERE c.client_id = $1`, client).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	var held bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.signing_keys WHERE instance_id = $1::uuid
		AND algorithm = 'RS256' AND state = 'active' AND purpose = 'oidc')`, instanceID).Scan(&held); err != nil {
		t.Fatal(err)
	}
	if !held {
		if got := put(map[string]any{"audience": audience, "remote_client_id": "x"}); got.code != http.StatusBadRequest {
			t.Errorf("RS256 with no key answered %d %s", got.code, got.body)
		}
	}

	if got := put(map[string]any{"audience": audience, "remote_client_id": "chat-client", "alg": string(keys.ES256),
		"scopes": []string{"chat.read"}, "resources": []string{"https://api.chat.example/"}}); got.code != http.StatusOK {
		t.Fatalf("the entry answered %d %s", got.code, got.body)
	}
	rec := call(t, s, http.MethodGet, path, testToken, nil)
	var list struct {
		Audiences []idJAGAudienceView `json:"audiences"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Audiences) != 1 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if got := list.Audiences[0]; got.Audience != audience || got.RemoteClientID != "chat-client" || got.Alg != "ES256" ||
		len(got.Scopes) != 1 || len(got.Resources) != 1 {
		t.Errorf("%+v", got)
	}
	remove := path + "?audience=" + url.QueryEscape(audience)
	if rec := call(t, s, http.MethodDelete, path, testToken, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("a removal naming nothing answered %d", rec.Code)
	}
	if rec := call(t, s, http.MethodDelete, remove, testToken, nil); rec.Code != http.StatusOK {
		t.Errorf("removing it answered %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, http.MethodDelete, remove, testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("removing it twice answered %d", rec.Code)
	}
	if rec := call(t, s, http.MethodPut, "/admin/clients/no-such-client/id-jag-audiences", testToken,
		map[string]any{"audience": audience, "remote_client_id": "x", "alg": "ES256"}); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown client answered %d", rec.Code)
	}
}

type idJAGAnswer struct {
	code int
	body string
}
