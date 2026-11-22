package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// A resource an organisation registered is found through a document served for it (12.15):
// all an MCP server needs is to name that document in its 401.

func resourceMetadataAt(t *testing.T, srv *Server, url string) (int, map[string]any, http.Header) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+store.ResourceMetadataPath+"{id}", srv.handleResourceMetadata)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Host = "attacker.test"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body, rec.Header()
}

func TestARegisteredResourcePublishesWhereToGetATokenForIt(t *testing.T) {
	ctx := context.Background()
	pool := ssfTestPool(t)
	q := newQueueTX(t)
	p := newSignalled(t, pool, q.srv.URL+"/jwks", "x")
	theirs := newSignalled(t, pool, q.srv.URL+"/jwks", "x")
	srv := &Server{db: pool, log: slog.New(slog.NewTextHandler(io.Discard, nil)), instanceID: p.instanceID,
		cfg: oidc.Config{Issuer: "https://id.example/"}}

	const resource = "https://mcp.example.test/sse"
	if err := store.SetResourceServer(ctx, pool, p.orgID, resource, "Tools", []string{"tools.read", "tools.run"}); err != nil {
		t.Fatal(err)
	}
	listed, err := store.ResourceServers(ctx, pool, p.orgID)
	if err != nil || len(listed) != 1 {
		t.Fatalf("%v, %d resources", err, len(listed))
	}
	path := listed[0].MetadataURL[strings.Index(listed[0].MetadataURL, "/.well-known/"):]
	code, md, header := resourceMetadataAt(t, srv, path)
	if code != http.StatusOK {
		t.Fatalf("answered %d", code)
	}
	if md["resource"] != resource {
		t.Errorf("resource is %v: a client compares this with where it was sent away from", md["resource"])
	}
	as, _ := md["authorization_servers"].([]any)
	if len(as) != 1 || as[0] != "https://id.example" {
		t.Errorf("authorization servers are %v, and the Host header was attacker.test", md["authorization_servers"])
	}
	if md["resource_name"] != "Tools" {
		t.Errorf("named %v", md["resource_name"])
	}
	scopes, _ := md["scopes_supported"].([]any)
	if len(scopes) != 2 || scopes[0] != "tools.read" {
		t.Errorf("scopes are %v", md["scopes_supported"])
	}
	if !strings.Contains(header.Get("Content-Type"), "application/json") {
		t.Errorf("served as %q", header.Get("Content-Type"))
	}

	// A name and scopes nobody gave are not invented.
	if err := store.SetResourceServer(ctx, pool, p.orgID, resource, "", []string{}); err != nil {
		t.Fatal(err)
	}
	if _, md, _ := resourceMetadataAt(t, srv, path); md["resource_name"] != nil || md["scopes_supported"] != nil {
		t.Errorf("an unnamed resource reads %v", md)
	}

	// Another instance's server has never heard of it.
	other := &Server{db: pool, log: srv.log, instanceID: theirs.instanceID, cfg: srv.cfg}
	if code, _, _ := resourceMetadataAt(t, other, path); code != http.StatusNotFound {
		t.Errorf("another instance answered %d", code)
	}
	for _, wrong := range []string{"not-a-uuid", "00000000-0000-0000-0000-000000000000", "'; DROP TABLE x"} {
		if code, _, _ := resourceMetadataAt(t, srv, store.ResourceMetadataPath+strings.ReplaceAll(wrong, " ", "%20")); code != http.StatusNotFound {
			t.Errorf("%q answered %d", wrong, code)
		}
	}
	if err := store.RemoveResourceServer(ctx, pool, p.orgID, resource); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := resourceMetadataAt(t, srv, path); code != http.StatusNotFound {
		t.Errorf("a removed resource answered %d", code)
	}
}
