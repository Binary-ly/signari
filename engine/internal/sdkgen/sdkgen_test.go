package sdkgen

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var root = filepath.Join("..", "..", "..")

var (
	sdkOut = flag.String("sdk-out", "", "write the generated clients under this root, as sdk/ is laid out")
	docIn  = flag.String("openapi", filepath.Join(root, "docs", "admin-openapi.json"), "the OpenAPI document")
)

// outputs are the generated files, by their place under the repository.
var outputs = map[string]func([]byte) ([]byte, error){
	filepath.Join("sdk", "go", "signariadmin", "signariadmin.go"): Go,
	filepath.Join("sdk", "typescript", "src", "index.ts"):         TypeScript,
	filepath.Join("docs", "admin-api-reference.md"):               Markdown,
}

// The committed clients are the ones docs/admin-openapi.json makes (6.18).
// Regenerate them with `go test ./internal/sdkgen -run TheClientsAreCurrent
// -sdk-out <dir>`, after the document itself.
func TestTheClientsAreCurrent(t *testing.T) {
	doc, err := os.ReadFile(*docIn)
	if err != nil {
		t.Fatal(err)
	}
	for rel, gen := range outputs {
		got, err := gen(doc)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if *sdkOut != "" {
			path := filepath.Join(*sdkOut, rel)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		committed, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if !bytes.Equal(got, committed) {
			t.Errorf("%s is not the client docs/admin-openapi.json makes; regenerate it with -sdk-out", rel)
		}
	}
}

// Every operation is a method of both clients, named for its operationId:
// a route the router registers cannot be missing from either.
func TestEveryOperationIsAMethodOfBothClients(t *testing.T) {
	doc, err := os.ReadFile(*docIn)
	if err != nil {
		t.Fatal(err)
	}
	_, ops, err := operations(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) < 100 {
		t.Fatalf("the document has %d operations; it is being read wrongly", len(ops))
	}
	goSrc, err := Go(doc)
	if err != nil {
		t.Fatal(err)
	}
	tsSrc, err := TypeScript(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		name := pascal(op.ID)
		if !strings.Contains(string(goSrc), "func (c *Client) "+name+"(") {
			t.Errorf("%s %s has no Go method %s", op.method, op.path, name)
		}
		if !strings.Contains(string(tsSrc), "  "+strings.ToLower(name[:1])+name[1:]+"(") {
			t.Errorf("%s %s has no TypeScript method", op.method, op.path)
		}
	}
}

func TestNamesReadAsGoNames(t *testing.T) {
	for in, want := range map[string]string{"patch_users_userID": "PatchUsersUserID", "client_id": "ClientID",
		"redirect_uris": "RedirectURIs", "get_organizations_orgID_identity_providers_slug": "GetOrganizationsOrgIDIdentityProvidersSlug",
		"x5c": "X5c", "2fa": "X2fa"} {
		if got := pascal(in); got != want {
			t.Errorf("pascal(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"userID": "userID", "sid": "sid", "IDPslug": "idPslug", "type": "typeParam"} {
		if got := camel(in); got != want {
			t.Errorf("camel(%q) = %q, want %q", in, got, want)
		}
	}
}
