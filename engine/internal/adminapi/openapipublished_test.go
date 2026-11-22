package adminapi

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var openAPIOut = flag.String("openapi-out", "", "write the OpenAPI document here, to copy over "+
	"docs/admin-openapi.json")

// The published OpenAPI document is the one the router draws (6.18): what
// the generated clients in sdk/ are made from, and what an integrator reads
// without running a server. Regenerate it with `go test ./internal/adminapi
// -run ThePublishedOpenAPIDocumentIsCurrent -openapi-out <file>` and copy the
// file over docs/admin-openapi.json; then regenerate the clients.
func TestThePublishedOpenAPIDocumentIsCurrent(t *testing.T) {
	s, _ := newTestServer(t)
	got, err := json.MarshalIndent(openAPIDoc(t, s), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *openAPIOut != "" {
		if err := os.WriteFile(*openAPIOut, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	published, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "admin-openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, published) {
		t.Error("docs/admin-openapi.json is not the document the router draws; regenerate it with -openapi-out, " +
			"then the clients in sdk/")
	}
}
