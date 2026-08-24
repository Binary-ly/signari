package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/ssf"
)

// SSF §7.2: the document "MUST be returned using the "application/json" content
// type", and §7.2.1: it "MUST be queried using an HTTP "GET" request".
//
// This engine transmits SETs and served no configuration document at all until
// this pass — a receiver could not discover our issuer, our keys, or which
// delivery method we speak without being told out of band.
func TestSSFConfigurationIsServedAtTheWellKnownPath(t *testing.T) {
	f := newTokenFixture(t)

	req := httptest.NewRequest(http.MethodGet, ssf.WellKnownBase, nil)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s gave %d: %s", ssf.WellKnownBase, rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q; §7.2 requires application/json", ct)
	}

	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("the document is not JSON: %v\n%s", err, rec.Body.String())
	}

	// §7.1: issuer is REQUIRED and MUST be identical to the `iss` in our SETs.
	// That second half is the one with teeth — §4.1.6 makes a receiver reject
	// any SET whose iss does not match what it has for the stream, so a document
	// that disagrees with our signatures makes us unsubscribable.
	wantIss := strings.TrimRight(f.srv.cfg.Issuer, "/")
	if doc["issuer"] != wantIss {
		t.Errorf("issuer = %v, want %q — the value we actually sign SETs with",
			doc["issuer"], wantIss)
	}
	if doc["spec_version"] != "1_0" {
		t.Errorf("spec_version = %v, want \"1_0\"; absent means a receiver assumes "+
			"the 1_0-ID1 implementer's draft", doc["spec_version"])
	}
	if doc["jwks_uri"] == nil || doc["jwks_uri"] == "" {
		t.Error("jwks_uri is missing; §7.1 requires it of a transmitter that signs")
	}
	methods, _ := doc["delivery_methods_supported"].([]any)
	got := map[string]bool{}
	for _, m := range methods {
		if s, ok := m.(string); ok {
			got[s] = true
		}
	}
	if len(methods) != 2 || !got[ssf.DeliveryPush] || !got[ssf.DeliveryPoll] {
		t.Errorf("delivery_methods_supported = %v, want push and poll (%s, %s)",
			methods, ssf.DeliveryPush, ssf.DeliveryPoll)
	}
}

// The jwks_uri we publish must be the one that actually serves our keys.
//
// A discovery document is only worth having if following it works. This fetches
// the advertised URL through the same router and checks a key set comes back —
// the failure it prevents is a plausible-looking path that 404s, which a
// receiver discovers at the moment it tries to verify its first event.
func TestTheAdvertisedJWKSURIActuallyServesKeys(t *testing.T) {
	f := newTokenFixture(t)

	req := httptest.NewRequest(http.MethodGet, ssf.WellKnownBase, nil)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	raw, _ := doc["jwks_uri"].(string)
	if raw == "" {
		t.Fatal("no jwks_uri to follow")
	}
	// Strip the issuer origin: the router serves paths, not absolute URLs.
	path := raw
	if i := strings.Index(raw, "://"); i >= 0 {
		if j := strings.Index(raw[i+3:], "/"); j >= 0 {
			path = raw[i+3+j:]
		}
	}
	req2 := httptest.NewRequest(http.MethodGet, path, nil)
	rec2 := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("the advertised jwks_uri %q (path %q) gave %d; a receiver "+
			"following our own discovery document cannot verify our events",
			raw, path, rec2.Code)
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("the advertised jwks_uri did not return a key set: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Error("the advertised jwks_uri returned an empty key set")
	}
}
