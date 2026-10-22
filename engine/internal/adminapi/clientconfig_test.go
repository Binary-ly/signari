package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
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

func containsString(v any, want string) bool {
	list, _ := v.([]any)
	for _, e := range list {
		if e == want {
			return true
		}
	}
	return false
}
