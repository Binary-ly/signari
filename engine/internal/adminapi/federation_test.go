package adminapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// An instance joins a federation, issues and revokes a Trust Mark, publishes
// one granted to it and delegates a type through the Admin API, as the
// federation and trust-mark commands do (6.07): every mark signed with the
// federation key and never the OIDC one, and only by a deployment-wide token.
func TestFederationAndTrustMarksAreManagedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	// With an active OIDC key, so a mark signed by the wrong key would be
	// signed rather than refused.
	id := newDriftKeyedInstance(t, s)
	entity, _, err := store.InstanceIssuer(ctx, s.db, id)
	if err != nil {
		t.Fatal(err)
	}
	base := "/admin/instances/" + id
	errorOf := func(token, method, path string, body any, want int) string {
		t.Helper()
		rec := call(t, s, method, path, token, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Errorf("%s %s answered %d, want %d: %s", method, path, rec.Code, want, rec.Body.String())
		}
		e, _ := out["error"].(string)
		return e
	}
	orgToken := mintToken(t, s, "federation-org-scoped", anyOrgID(t, s), []string{ScopeOrganizationsWrite,
		ScopeConfigRead}, nil)
	if e := errorOf(orgToken, http.MethodPut, base+"/federation", map[string]any{"authority_hints": []string{
		"https://anchor.example.test"}}, http.StatusForbidden); e != "outside_token_organisation" {
		t.Errorf("an organisation's token answered %q", e)
	}
	const markType = "https://marks.example.test/privacy"
	issue := map[string]any{"type": markType, "subject": "https://rp.example.test", "lifetime_s": 3600}
	if e := errorOf(testToken, http.MethodPost, base+"/trust-marks", issue, http.StatusConflict); e != "federation_not_enabled" {
		t.Errorf("issuing before federation was enabled answered %q", e)
	}
	if e := errorOf(testToken, http.MethodPut, base+"/federation", map[string]any{}, http.StatusBadRequest); e != "invalid_federation" {
		t.Errorf("no authority hints answered %q", e)
	}

	rec := call(t, s, http.MethodPut, base+"/federation", testToken, map[string]any{
		"authority_hints": []string{"https://anchor.example.test"}, "trust_anchor_hints": []string{"https://anchor.example.test"}})
	var enabled struct {
		GeneratedKey    string `json:"generated_key"`
		RestartRequired bool   `json:"restart_required"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &enabled)
	if rec.Code != http.StatusOK || enabled.GeneratedKey == "" || !enabled.RestartRequired {
		t.Fatalf("enabling: %d %s", rec.Code, rec.Body.String())
	}
	// A second change keeps the key and what it does not name.
	rec = call(t, s, http.MethodPut, base+"/federation", testToken, map[string]any{
		"authority_hints": []string{"https://anchor.example.test"}, "organization_name": "Example"})
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"restart_required":true`) {
		t.Errorf("changing the name: %d %s", rec.Code, rec.Body.String())
	}
	got := call(t, s, http.MethodGet, base+"/federation", testToken, nil)
	if !strings.Contains(got.Body.String(), `"organization_name":"Example"`) ||
		!strings.Contains(got.Body.String(), `"trust_anchor_hints":["https://anchor.example.test"]`) {
		t.Errorf("the federation reads %s", got.Body.String())
	}

	rec = call(t, s, http.MethodPost, base+"/trust-marks", testToken, issue)
	var issued struct {
		TrustMark string `json:"trust_mark"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &issued)
	if rec.Code != http.StatusCreated || issued.TrustMark == "" {
		t.Fatalf("issuing: %d %s", rec.Code, rec.Body.String())
	}
	// Signed by the key federation enable generated.
	header, err := base64.RawURLEncoding.DecodeString(strings.Split(issued.TrustMark, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var h struct{ Kid, Typ string }
	_ = json.Unmarshal(header, &h)
	if h.Kid != enabled.GeneratedKey {
		t.Errorf("the mark was signed by %q, want the federation key %q", h.Kid, enabled.GeneratedKey)
	}
	if e := errorOf(testToken, http.MethodPost, base+"/trust-marks", map[string]any{"type": "privacy",
		"subject": "https://rp.example.test"}, http.StatusBadRequest); e != "federation_refused" {
		t.Errorf("a type that is not a URL answered %q", e)
	}

	revoke := map[string]any{"type": markType, "subject": "https://rp.example.test", "reason": "lapsed"}
	if rec := call(t, s, http.MethodPost, base+"/trust-marks/revoke", testToken, revoke); rec.Code != http.StatusOK {
		t.Fatalf("revoking: %d %s", rec.Code, rec.Body.String())
	}
	if e := errorOf(testToken, http.MethodPost, base+"/trust-marks/revoke", revoke, http.StatusNotFound); e != "trust_mark_not_found" {
		t.Errorf("revoking it again answered %q", e)
	}

	// Holding a mark another issuer granted, and refusing one granted to
	// somebody else.
	mark, issuer := driftTrustMarkFor(t, s, entity)
	theirs, _ := driftTrustMarkFor(t, s, "https://someone-else.example.test")
	if e := errorOf(testToken, http.MethodPut, base+"/held-trust-marks", map[string]string{"trust_mark": theirs},
		http.StatusBadRequest); e != "federation_refused" {
		t.Errorf("a mark issued to another entity answered %q", e)
	}
	if rec := call(t, s, http.MethodPut, base+"/held-trust-marks", testToken, map[string]string{"trust_mark": mark}); rec.Code != http.StatusOK {
		t.Fatalf("accepting: %d %s", rec.Code, rec.Body.String())
	}
	list := call(t, s, http.MethodGet, base+"/trust-marks", testToken, nil)
	if !strings.Contains(list.Body.String(), `"status":"revoked"`) || !strings.Contains(list.Body.String(), `"published":true`) ||
		strings.Contains(list.Body.String(), issued.TrustMark) {
		t.Errorf("the trust marks read %s", list.Body.String())
	}
	drop := base + "/held-trust-marks?type=" + url.QueryEscape(markType) + "&issuer=" + url.QueryEscape(issuer)
	if e := errorOf(testToken, http.MethodDelete, drop, nil, http.StatusNotFound); e != "trust_mark_not_found" {
		// The mark held is driftMarkType, not this one.
		t.Errorf("dropping a type it does not hold answered %q", e)
	}
	drop = base + "/held-trust-marks?type=" + url.QueryEscape(driftMarkType) + "&issuer=" + url.QueryEscape(issuer)
	if rec := call(t, s, http.MethodDelete, drop, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("dropping: %d %s", rec.Code, rec.Body.String())
	}

	rec = call(t, s, http.MethodPost, base+"/trust-mark-delegations", testToken, map[string]any{"type": markType,
		"delegate": "https://delegate.example.test", "lifetime_s": 3600})
	var delegated struct{ Delegation string }
	_ = json.Unmarshal(rec.Body.Bytes(), &delegated)
	if rec.Code != http.StatusCreated || strings.Count(delegated.Delegation, ".") != 2 {
		t.Errorf("delegating: %d %s", rec.Code, rec.Body.String())
	}
}
