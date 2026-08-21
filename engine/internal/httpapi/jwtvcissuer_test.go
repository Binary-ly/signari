package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTheJWTVCIssuerMetadataLetsAVerifierFindOurKey(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)

	req := httptest.NewRequest(http.MethodGet, jwtVCIssuerPath(f.srv.cfg.Issuer), nil)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("%s gave %d; a verifier following §2.5 has no other mechanism "+
			"available and must reject every credential we issue",
			jwtVCIssuerPath(f.srv.cfg.Issuer), rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body: %v", err)
	}

	// §3.3: "The issuer value returned MUST be identical to the iss value of the
	// Issuer-signed JWT. If these values are not identical, the data contained in
	// the response MUST NOT be used." So this is not decorative — a mismatch
	// makes the whole document unusable.
	if got["issuer"] != f.srv.cfg.Issuer {
		t.Errorf("issuer = %v, want %q identical to the credential's iss",
			got["issuer"], f.srv.cfg.Issuer)
	}

	// §3.2: "MUST include either jwks_uri or jwks ... but not both."
	_, byRef := got["jwks_uri"]
	_, byValue := got["jwks"]
	switch {
	case byRef && byValue:
		t.Error("both jwks_uri and jwks are present; §3.2 permits exactly one")
	case !byRef && !byValue:
		t.Error("neither jwks_uri nor jwks is present, so there is no key to find")
	}

	// The reference must actually resolve on this server, or the document sends a
	// verifier somewhere that does not answer.
	if uri, _ := got["jwks_uri"].(string); uri != "" {
		path := uri[len(f.srv.cfg.Issuer):]
		jr := httptest.NewRequest(http.MethodGet, path, nil)
		jrec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(jrec, jr)
		if jrec.Code != http.StatusOK {
			t.Errorf("jwks_uri %q gave %d", uri, jrec.Code)
		}
		var ks map[string]any
		_ = json.Unmarshal(jrec.Body.Bytes(), &ks)
		if keys, _ := ks["keys"].([]any); len(keys) == 0 {
			t.Errorf("the referenced key set carries no keys: %v", ks)
		}
	}
}

// §3: the well-known string is INSERTED between host and path, not appended.
// A deployment whose issuer carries a path is otherwise published at a location
// no verifier constructs.
func TestTheWellKnownPathIsInsertedNotAppended(t *testing.T) {
	for _, tc := range []struct{ issuer, want string }{
		{"https://example.com", "/.well-known/jwt-vc-issuer"},
		{"https://example.com/", "/.well-known/jwt-vc-issuer"},
		{"https://example.com/tenant/1234", "/.well-known/jwt-vc-issuer/tenant/1234"},
		{"https://example.com/tenant/1234/", "/.well-known/jwt-vc-issuer/tenant/1234"},
	} {
		if got := jwtVCIssuerPath(tc.issuer); got != tc.want {
			t.Errorf("jwtVCIssuerPath(%q) = %q, want %q — §3.1 requires the "+
				"terminating slash removed and the suffix inserted before the path",
				tc.issuer, got, tc.want)
		}
	}
}

// A deployment that issues no credentials publishes nothing, the same rule the
// credential issuer metadata follows.
func TestNoCredentialsMeansNoIssuerMetadata(t *testing.T) {
	f := newTokenFixture(t)
	req := httptest.NewRequest(http.MethodGet, jwtVCIssuerPath(f.srv.cfg.Issuer), nil)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Error("an issuer with no credential configurations published JWT VC " +
			"issuer metadata, which advertises a capability it does not have")
	}
}
