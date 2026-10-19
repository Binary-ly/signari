package ssf

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Every event this transmitter advertises is one it builds. Credential-change
// was advertised and never built, so a receiver subscribing to it waited for a
// signal that could not come. Read off the source: an advertised event must
// appear as the Type of an Event literal in a non-test file of this package.
func TestEverySupportedEventIsBuilt(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	constants := map[string]string{} // name -> value, for the Event* constants
	built := map[string]bool{}       // constant names used as an Event's Type
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
			switch v := n.(type) {
			case *ast.ValueSpec:
				for i, id := range v.Names {
					if i < len(v.Values) && strings.HasPrefix(id.Name, "Event") {
						if lit, ok := v.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							s, _ := strconv.Unquote(lit.Value)
							constants[id.Name] = s
						}
					}
				}
			case *ast.CompositeLit:
				if typ, ok := v.Type.(*ast.Ident); !ok || typ.Name != "Event" {
					return true
				}
				for _, el := range v.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Type" {
						if val, ok := kv.Value.(*ast.Ident); ok {
							built[val.Name] = true
						}
					}
				}
			}
			return true
		})
	}
	if len(constants) < 2 {
		t.Fatalf("read %d event constants; the walk is not reading the package", len(constants))
	}
	builtValues := map[string]bool{}
	for name := range built {
		builtValues[constants[name]] = true
	}
	for _, e := range SupportedEvents() {
		if !builtValues[e] {
			t.Errorf("%s is advertised in SupportedEvents and no Event literal in this package "+
				"is built with it, so a receiver that subscribes waits forever; emit it or "+
				"stop advertising it", e)
		}
	}
}
