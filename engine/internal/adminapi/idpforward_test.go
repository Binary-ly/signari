package adminapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// What a sign-in passes on to a provider is opted in here (8.36). A name nothing would
// pass on, or a provider with no authorization request to carry one, is refused: a list
// that reads as set and does nothing has the operator believing the provider is asked.
func TestWhatAProviderIsToldIsSetThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	org, _, path := newDriftIdP(t, s, "oidc")
	_, _, saml := newDriftIdP(t, s, "saml")
	patch := func(at string, body map[string]any, want int) string {
		t.Helper()
		rec := call(t, s, http.MethodPatch, at, testToken, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Fatalf("%v answered %d, want %d: %s", body, rec.Code, want, rec.Body.String())
		}
		e, _ := out["error"].(string)
		return e
	}
	listed := func() string {
		t.Helper()
		return call(t, s, http.MethodGet, "/admin/organizations/"+org+"/identity-providers", testToken, nil).Body.String()
	}

	if !strings.Contains(listed(), `"forward_parameters":[]`) {
		t.Errorf("a new provider is told something: %s", listed())
	}
	bad := http.StatusBadRequest
	if e := patch(path, map[string]any{"forward_parameters": []string{"prompt", "scope"}}, bad); e != "invalid_identity_provider" {
		t.Errorf("a name nothing passes on answered %q", e)
	}
	if e := patch(saml, map[string]any{"forward_parameters": []string{"prompt"}}, bad); e != "invalid_identity_provider" {
		t.Errorf("a SAML provider answered %q", e)
	}
	patch(path, map[string]any{"forward_parameters": []string{"prompt", "login_hint"}}, http.StatusOK)
	if !strings.Contains(listed(), `"forward_parameters":["prompt","login_hint"]`) {
		t.Errorf("the listing does not say so: %s", listed())
	}
	patch(path, map[string]any{"enabled": true}, http.StatusOK)
	if !strings.Contains(listed(), `"forward_parameters":["prompt","login_hint"]`) {
		t.Errorf("another change cleared it: %s", listed())
	}
	patch(path, map[string]any{"forward_parameters": []string{}}, http.StatusOK)
	if !strings.Contains(listed(), `"forward_parameters":[]`) {
		t.Errorf("an empty list did not tell it nothing again: %s", listed())
	}
}
