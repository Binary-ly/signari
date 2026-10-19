package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
)

// RFC 8414 §3 metadata is served where §3.1 puts it, between the issuer's host
// and its path, and carries the issuer exactly (§3.3). It was not routed while
// docs/mcp-authorization.md said it was, and MCP clients look there first.
func TestAuthorizationServerMetadataIsWhereRFC8414PutsIt(t *testing.T) {
	f := newTokenFixture(t)
	get := func(srv http.Handler, path string) (int, map[string]any) {
		t.Helper()
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		var doc map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &doc)
		return rec.Code, doc
	}

	code, doc := get(f.srv.Routes(), "/.well-known/oauth-authorization-server")
	if code != http.StatusOK || doc["issuer"] != f.srv.cfg.Issuer || doc["token_endpoint"] == nil {
		t.Fatalf("the RFC 8414 document answered %d with issuer %v", code, doc["issuer"])
	}

	// An issuer with a path: inserted before it. (A terminating slash, which
	// §3.1 has removed first, cannot arise: New refuses such an issuer.)
	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	set, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "https://as.example.test/tenant1"
	srv, err := New(oidc.Config{Issuer: issuer, Keys: set}, f.pool,
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code, doc := get(srv.Routes(), "/.well-known/oauth-authorization-server/tenant1"); code != http.StatusOK ||
		doc["issuer"] != srv.cfg.Issuer {
		t.Errorf("for issuer %s the document at the inserted path answered %d with issuer %v",
			issuer, code, doc["issuer"])
	}
}
