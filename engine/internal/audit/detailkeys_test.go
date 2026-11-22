package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// nameKeys put a person's name or address into a row's detail, which is
// plaintext inside the hash chain: append-only, and out of erasure's reach,
// which removes a subject's key and so only what was written by subject id.
var nameKeys = map[string]bool{
	"username": true, "user_name": true, "uid": true, "email": true, "mail": true, "upn": true,
}

// No audit event in the engine carries a person's name or address in its
// detail; it names them by SubjectID and ActorID (3.35). The LDAP writer's
// events carried the bound account's username and the entry's. Read from
// the source, every package, so a new event cannot opt out.
func TestNoAuditRowNamesAPerson(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	events := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isEvent(lit.Type) {
				return true
			}
			events++
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "Detail" {
					continue
				}
				detail, ok := kv.Value.(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, de := range detail.Elts {
					dkv, ok := de.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if b, ok := dkv.Key.(*ast.BasicLit); ok {
						if key, _ := strconv.Unquote(b.Value); nameKeys[key] {
							pos := fset.Position(b.Pos())
							rel, _ := filepath.Rel(root, pos.Filename)
							found = append(found, rel+":"+strconv.Itoa(pos.Line)+" "+strconv.Quote(key))
						}
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if events < 100 {
		t.Fatalf("only %d audit events found under %s; reading the tree wrong", events, root)
	}
	if len(found) > 0 {
		t.Errorf("%d audit event detail(s) name a person; use SubjectID and ActorID:\n  %s",
			len(found), strings.Join(found, "\n  "))
	}
}

func isEvent(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		return v.Sel.Name == "Event"
	case *ast.Ident:
		return v.Name == "Event"
	}
	return false
}
