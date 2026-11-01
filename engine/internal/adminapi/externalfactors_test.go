package adminapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// A service is registered, read back and forgotten as `signari external-factor`
// does it, and what it could never answer, or should never be believed for, is
// refused before it is stored.
func TestAnExternalFactorIsRegisteredAndForgottenThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	path := "/admin/organizations/" + org + "/external-factors/push"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := func() map[string]any {
		return map[string]any{"url": "https://factor.example/ask", "issuer": "https://factor.example",
			"amr": []string{"otp"}, "jwks": json.RawMessage(publicJWKS(t))}
	}
	for why, change := range map[string]func(map[string]any){
		"a private key":     func(b map[string]any) { b["jwks"] = json.RawMessage(keySetOf(t, priv)) },
		"no keys":           func(b map[string]any) { b["jwks"] = json.RawMessage(`{"keys":[]}`) },
		"a plain http url":  func(b map[string]any) { b["url"] = "http://factor.example/ask" },
		"a url with a user": func(b map[string]any) { b["url"] = "https://me@factor.example/ask" },
		"no issuer":         func(b map[string]any) { delete(b, "issuer") },
		"no amr":            func(b map[string]any) { delete(b, "amr") },
		"a route for amr":   func(b map[string]any) { b["amr"] = []string{"pwd"} },
	} {
		body := good()
		change(body)
		rec := call(t, s, http.MethodPut, path, testToken, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusBadRequest || out["error"] != "invalid_external_factor" {
			t.Errorf("%s answered %d %v", why, rec.Code, out)
		}
	}
	if got, _ := store.ExternalFactors(ctx, s.db, org); len(got) != 0 {
		t.Fatalf("a refused service was stored: %+v", got)
	}

	if rec := call(t, s, http.MethodPut, path, testToken, good()); rec.Code != http.StatusOK {
		t.Fatalf("registering: %d %s", rec.Code, rec.Body.String())
	}
	rec := call(t, s, http.MethodGet, "/admin/organizations/"+org+"/external-factors", testToken, nil)
	body := rec.Body.String()
	if !strings.Contains(body, `"name":"push"`) || !strings.Contains(body, `"amr":["otp"]`) ||
		!strings.Contains(body, `"keys":1`) || strings.Contains(body, `"crv"`) {
		t.Errorf("the services read %s", body)
	}

	// A flow that names it holds it in place.
	if _, err := store.ApplySignInFlow(ctx, s.db, org, []byte(`version: 1
flows:
  - name: with-a-service
    on: authentication
    stages:
      - password
      - {stage: external_factor, factor: push}
      - session
    tests:
      - name: asked
        given: {}
        expect: [password, external_factor, session]
`)); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, s, http.MethodDelete, path, testToken, nil); rec.Code != http.StatusConflict ||
		!strings.Contains(rec.Body.String(), "external_factor_in_use") {
		t.Errorf("forgetting a service the flow names answered %d %s", rec.Code, rec.Body.String())
	}
	if _, err := s.db.Exec(ctx, `DELETE FROM core.sign_in_flows WHERE org_id = $1::uuid`, org); err != nil {
		t.Fatal(err)
	}

	if rec := call(t, s, http.MethodDelete, path, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("forgetting: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodDelete, path, testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("forgetting a service forgotten answered %d", rec.Code)
	}
}
