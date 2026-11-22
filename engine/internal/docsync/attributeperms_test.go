package docsync

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An attribute's declaration says whether its subject may read it, write it,
// and must have it (user_readable, user_writable, required). The Admin API
// stored all three and nothing else read them, so they governed nothing: the
// inverse of the write-path guard, a setting with a writer and no reader on the
// path it claims to govern (5.05).
//
// So each must be consulted by a function on a person's own path -- in
// internal/httpapi or internal/store, outside the Admin API -- that reads the
// declarations. The functions that only load and save them do not count.
func TestEveryAttributePermissionIsConsultedOnThePersonsPath(t *testing.T) {
	root := repoRoot(t)
	loaders := map[string]bool{"Attributes": true, "UserAttributes": true, "DeclareAttribute": true}
	want := map[string]bool{"UserReadable": false, "UserWritable": false, "Required": false}
	fset := token.NewFileSet()
	for _, dir := range []string{"engine/internal/httpapi", "engine/internal/store"} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(root, dir, e.Name()), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil || loaders[fd.Name.Name] {
					continue
				}
				readsDeclarations := false
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok {
						switch fun := c.Fun.(type) {
						case *ast.Ident:
							readsDeclarations = readsDeclarations || fun.Name == "Attributes"
						case *ast.SelectorExpr:
							readsDeclarations = readsDeclarations || fun.Sel.Name == "Attributes"
						}
					}
					return true
				})
				if !readsDeclarations {
					continue
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if sel, ok := n.(*ast.SelectorExpr); ok {
						if _, tracked := want[sel.Sel.Name]; tracked {
							want[sel.Sel.Name] = true
						}
					}
					return true
				})
			}
		}
	}
	for field, consulted := range want {
		if !consulted {
			t.Errorf("an attribute's %s is stored and consulted by nothing on a person's own path: "+
				"the declaration says something no page or sign-up honours", field)
		}
	}
}
