package docsync

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// Every grant the token endpoint dispatches can be given to a client.
//
// The endpoint serves a grant only to a client registered for it, and
// `signari client set-grants` is the one way to register one. The command kept
// its own list of grants, which lacked CIBA, the UMA ticket grant and
// jwt-bearer: three protocols built, tested through SQL fixtures, documented,
// and refused as unauthorized_client to every client an operator could make.
// The command's list must be the endpoint's list, not a copy of it.
func TestEveryDispatchedGrantCanBeGivenToAClient(t *testing.T) {
	path := filepath.Join(repoRoot(t), "engine", "cmd", "signari", "main.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || spec.Names[0].Name != "knownGrantTypes" {
			return true
		}
		found = true
		var pkg, name string
		if sel, ok := spec.Values[0].(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok {
				pkg, name = id.Name, sel.Sel.Name
			}
		}
		if pkg != "oauth" || name != "GrantTypes" {
			t.Errorf("%s: knownGrantTypes is a list of its own; it must be oauth.GrantTypes, "+
				"the grants the token endpoint dispatches", fset.Position(spec.Pos()))
		}
		return false
	})
	if !found {
		t.Fatal("knownGrantTypes is gone from cmd/signari/main.go; find what set-grants checks " +
			"against now and point this test at it")
	}
}
