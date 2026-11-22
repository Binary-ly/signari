package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// The settings the CLI's verbs write are written by PATCH through the same
// store writers, and read back whole by GET (6.03).

func readClient(t *testing.T, s *Server, clientID string) map[string]any {
	t.Helper()
	rec := call(t, s, http.MethodGet, "/admin/clients/"+clientID, testToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	var c map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEveryClientSettingRoundTripsThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	client := newPreconditionClient(t, s)

	for _, c := range []struct {
		field string
		set   any
		want  any
	}{
		{"grant_types", []string{"authorization_code", "client_credentials"}, []any{"authorization_code", "client_credentials"}},
		{"dpop_bound_access_tokens", true, true},
		{"exchange_requires_audience_match", true, true},
		{"claims_redirect_uris", []string{"https://rp.example.test/claims"}, []any{"https://rp.example.test/claims"}},
		{"jwt_bearer_providers", []string{}, []any{}},
	} {
		rec := call(t, s, http.MethodPatch, "/admin/clients/"+client, testToken, map[string]any{c.field: c.set})
		if rec.Code != http.StatusOK {
			t.Errorf("setting %s: %d %s", c.field, rec.Code, rec.Body.String())
			continue
		}
		if got := readClient(t, s, client)[c.field]; fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s read back %v, want %v", c.field, got, c.want)
		}
	}

	// A pair, with the half not sent held at what it was.
	if rec := call(t, s, http.MethodPatch, "/admin/clients/"+client, testToken, map[string]any{
		"backchannel_token_delivery_mode": "ping", "backchannel_client_notification_endpoint": "https://rp.example.test/ciba",
	}); rec.Code != http.StatusOK {
		t.Fatalf("CIBA: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodPatch, "/admin/clients/"+client, testToken, map[string]any{
		"backchannel_client_notification_endpoint": "https://rp.example.test/ciba2",
	}); rec.Code != http.StatusOK {
		t.Fatalf("CIBA endpoint alone: %d %s", rec.Code, rec.Body.String())
	}
	got := readClient(t, s, client)
	if got["backchannel_token_delivery_mode"] != "ping" || got["backchannel_client_notification_endpoint"] != "https://rp.example.test/ciba2" {
		t.Errorf("CIBA read back %v / %v", got["backchannel_token_delivery_mode"], got["backchannel_client_notification_endpoint"])
	}

	if rec := call(t, s, http.MethodPatch, "/admin/clients/"+client, testToken, map[string]any{
		"allow_hybrid": true, "hybrid_review_by": "2027-01-31"}); rec.Code != http.StatusOK {
		t.Fatalf("hybrid: %d %s", rec.Code, rec.Body.String())
	}
	got = readClient(t, s, client)
	if got["allow_hybrid"] != true || got["hybrid_review_by"] != "2027-01-31" ||
		!containsString(got["response_types"], "code id_token") {
		t.Errorf("hybrid read back %v %v %v", got["allow_hybrid"], got["hybrid_review_by"], got["response_types"])
	}
	if rec := call(t, s, http.MethodPatch, "/admin/clients/"+client, testToken, map[string]any{"allow_hybrid": false}); rec.Code != http.StatusOK {
		t.Fatalf("hybrid off: %d %s", rec.Code, rec.Body.String())
	}
	got = readClient(t, s, client)
	if got["allow_hybrid"] != false || got["hybrid_review_by"] != nil || containsString(got["response_types"], "code id_token") {
		t.Errorf("hybrid off read back %v %v %v", got["allow_hybrid"], got["hybrid_review_by"], got["response_types"])
	}
}

func TestTheAPIRefusesWhatTheCLIRefuses(t *testing.T) {
	s, _ := newTestServer(t)
	client := newPreconditionClient(t, s)
	for why, body := range map[string]map[string]any{
		"a grant nothing dispatches":  {"grant_types": []string{"password"}},
		"no grants at all":            {"grant_types": []string{}},
		"push to plaintext":           {"backchannel_token_delivery_mode": "push", "backchannel_client_notification_endpoint": "http://rp.example.test/x"},
		"poll with an endpoint":       {"backchannel_token_delivery_mode": "poll", "backchannel_client_notification_endpoint": "https://rp.example.test/x"},
		"hybrid with no review date":  {"allow_hybrid": true},
		"a plaintext claims redirect": {"claims_redirect_uris": []string{"http://rp.example.test/claims"}},
		"a claims redirect fragment":  {"claims_redirect_uris": []string{"https://rp.example.test/claims#x"}},
		"an issuer this org lacks":    {"jwt_bearer_providers": []string{"no-such-issuer"}},
	} {
		before := readClient(t, s, client)
		rec := call(t, s, http.MethodPatch, "/admin/clients/"+client, testToken, body)
		// The refusal the shared rule makes, not any 400: a PATCH whose fields
		// the handler did not know was refused as having nothing to change,
		// and passed this test while setting nothing.
		var refused map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &refused)
		if rec.Code != http.StatusBadRequest || refused["error"] != "invalid_client_setting" {
			t.Errorf("%s answered %d %s", why, rec.Code, rec.Body.String())
		}
		if after := readClient(t, s, client); fmt.Sprint(after) != fmt.Sprint(before) {
			t.Errorf("%s was refused and still changed the client", why)
		}
	}
}

// The rest of a client's configuration: what only `signari apply`, the CLI's
// keys and TLS verbs, or nothing at all could set.
func TestTheRestOfAClientRoundTripsThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	client := newPreconditionClient(t, s)
	pub := `{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",` +
		`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"rt-1","use":"sig"}]}`

	set := map[string]any{
		"display_name":                        "Renamed by the API",
		"redirect_uris":                       []string{"https://rp.example.test/b", "https://rp.example.test/a"},
		"scopes":                              []string{"openid", "profile"},
		"initiate_login_uri":                  "https://rp.example.test/start",
		"logo_uri":                            "https://rp.example.test/logo.png",
		"backchannel_logout_uri":              "https://rp.example.test/bcl",
		"backchannel_logout_session_required": false,
		"jwks":                                json.RawMessage(pub),
		"tls_subject_dn":                      "CN=rp.example.test",
		"tls_bound_tokens":                    true,
	}
	if rec := call(t, s, http.MethodPatch, "/admin/clients/"+client, testToken, set); rec.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", rec.Code, rec.Body.String())
	}
	got := readClient(t, s, client)
	for field, want := range map[string]any{
		"display_name": "Renamed by the API", "redirect_uris": "[https://rp.example.test/a https://rp.example.test/b]",
		"scopes": "[openid profile]", "initiate_login_uri": "https://rp.example.test/start",
		"logo_uri": "https://rp.example.test/logo.png", "backchannel_logout_uri": "https://rp.example.test/bcl",
		"backchannel_logout_session_required": "false", "token_endpoint_auth_method": "private_key_jwt",
		"tls_subject_dn": "CN=rp.example.test", "tls_bound_tokens": "true",
	} {
		if fmt.Sprint(got[field]) != fmt.Sprint(want) {
			t.Errorf("%s read back %v, want %v", field, got[field], want)
		}
	}
	if jw, _ := got["jwks"].(map[string]any); len(jw) == 0 {
		t.Errorf("the key set was not stored: %v", got["jwks"])
	}
	// The secret went with the move to keys, as `client set-keys` drops it.
	var secret *string
	if err := s.db.QueryRow(t.Context(), `SELECT client_secret_hash FROM core.clients WHERE client_id = $1`,
		client).Scan(&secret); err != nil || secret != nil {
		t.Errorf("the client kept its secret beside its keys: %v %v", secret, err)
	}
	// Only the bound-tokens switch: the rule it already has stays.
	if rec := call(t, s, http.MethodPatch, "/admin/clients/"+client, testToken, map[string]any{"tls_bound_tokens": false}); rec.Code != http.StatusOK {
		t.Fatalf("bound tokens alone: %d %s", rec.Code, rec.Body.String())
	}
	if got := readClient(t, s, client); got["tls_subject_dn"] != "CN=rp.example.test" || got["tls_bound_tokens"] != false {
		t.Errorf("bound tokens alone moved the rule: %v %v", got["tls_subject_dn"], got["tls_bound_tokens"])
	}
}

func TestTheAPIRefusesWhatApplyAndTheVerbsRefuse(t *testing.T) {
	s, _ := newTestServer(t)
	client := newPreconditionClient(t, s)
	for why, c := range map[string]struct {
		body map[string]any
		code string
	}{
		"a private key":            {map[string]any{"jwks": json.RawMessage(`{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}]}`)}, "invalid_client_setting"},
		"a symmetric key":          {map[string]any{"jwks": json.RawMessage(`{"keys":[{"kty":"oct","k":"c2VjcmV0LXNlY3JldC1zZWNyZXQ"}]}`)}, "invalid_client_setting"},
		"two TLS rules":            {map[string]any{"tls_subject_dn": "CN=a", "tls_san_dns": "a.example.test"}, "invalid_client_setting"},
		"no redirect URIs":         {map[string]any{"redirect_uris": []string{}}, "invalid_client_setting"},
		"a wildcard redirect":      {map[string]any{"redirect_uris": []string{"https://*.example.test/cb"}}, "invalid_client_setting"},
		"an undeclared scope":      {map[string]any{"scopes": []string{"openid", "no-such-scope-here"}}, "invalid_client_setting"},
		"a plaintext launch URL":   {map[string]any{"initiate_login_uri": "http://rp.example.test/start"}, "invalid_client_setting"},
		"hidden with a launch URL": {map[string]any{"initiate_login_uri": "https://rp.example.test/s", "portal_hidden": true}, "invalid_client_setting"},
		"an empty name":            {map[string]any{"display_name": "  "}, "invalid_client_setting"},
		"a plaintext back channel": {map[string]any{"backchannel_logout_uri": "http://rp.example.test/bcl"}, "invalid_logout_uri"},
		"a back channel fragment":  {map[string]any{"backchannel_logout_uri": "https://rp.example.test/bcl#f"}, "invalid_logout_uri"},
	} {
		before := readClient(t, s, client)
		rec := call(t, s, http.MethodPatch, "/admin/clients/"+client, testToken, c.body)
		var refused map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &refused)
		if rec.Code != http.StatusBadRequest || refused["error"] != c.code {
			t.Errorf("%s answered %d %s", why, rec.Code, rec.Body.String())
		}
		if after := readClient(t, s, client); fmt.Sprint(after) != fmt.Sprint(before) {
			t.Errorf("%s was refused and still changed the client", why)
		}
	}
}

// A field PATCH cannot set is refused by name, not dropped with a 200.
func TestAClientPatchRefusesAFieldItCannotSet(t *testing.T) {
	s, _ := newTestServer(t)
	client := newPreconditionClient(t, s)
	for _, field := range []string{"client_type", "org_id", "created_at", "redirect_uri"} {
		rec := call(t, s, http.MethodPatch, "/admin/clients/"+client, testToken, map[string]any{field: "x", "enabled": true})
		var refused map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &refused)
		if rec.Code != http.StatusBadRequest || refused["error"] != "invalid_json" ||
			!strings.Contains(fmt.Sprint(refused["detail"]), field) {
			t.Errorf("%s: %d %s", field, rec.Code, rec.Body.String())
		}
	}
}

func containsString(v any, want string) bool {
	list, _ := v.([]any)
	for _, e := range list {
		if e == want {
			return true
		}
	}
	return false
}
