package adminapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Nothing is hashed while the configuration version is held.
//
// mutate and mutateIf hold core.config_version for the length of their
// transaction, and every administrative write queues behind it. The hasher is
// shared with the sign-in paths and waits for a slot, so a password hashed
// inside one of those closures -- creating or updating a user did -- held every
// write in the deployment for as long as a sign-in flood kept the slots busy.
// Hash first, then write.
func TestNothingIsHashedUnderTheVersionLock(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	closures := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "mutate" && sel.Sel.Name != "mutateIf") || len(call.Args) == 0 {
				return true
			}
			body, ok := call.Args[len(call.Args)-1].(*ast.FuncLit)
			if !ok {
				return true
			}
			closures++
			ast.Inspect(body, func(m ast.Node) bool {
				if s, ok := m.(*ast.SelectorExpr); ok && s.Sel.Name == "hasher" {
					t.Errorf("%s: a %s closure uses the hasher; hash before taking the "+
						"configuration version", fset.Position(s.Pos()), sel.Sel.Name)
				}
				return true
			})
			return true
		})
	}
	if closures < 10 {
		t.Fatalf("found only %d mutate closures; the scan is not seeing the handlers", closures)
	}
}
