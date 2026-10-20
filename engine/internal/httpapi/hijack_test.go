package httpapi

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"signari.dev/engine/internal/metrics"
)

// Every wrapper a request passes through leaves the connection reachable. A
// remote-access session upgrades to a websocket, which hijacks it, and a
// wrapper that hid it answered every session 501 "does not implement
// http.Hijacker" (3.32).
func TestEveryWrapperLeavesTheConnectionHijackable(t *testing.T) {
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	hijack := func(herr *error) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _, *herr = http.NewResponseController(w).Hijack()
		})
	}
	for name, wrap := range map[string]func(http.Handler) http.Handler{
		"recovery":   s.withRecovery,
		"access log": s.withAccessLog,
		"metrics":    metrics.NewEngine().Middleware,
	} {
		var herr error
		w := &hijackable{ResponseWriter: httptest.NewRecorder()}
		wrap(hijack(&herr)).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/rac/connect/x", nil))
		if errors.Is(herr, http.ErrNotSupported) || !w.hijacked {
			t.Errorf("through %s: %v (hijacked %v)", name, herr, w.hijacked)
		}
	}
}

// Every type in the engine that embeds an http.ResponseWriter declares
// Unwrap, so the next wrapper someone writes cannot hide the connection the
// way recovery's and the metrics middleware's did. Read from the source.
func TestEveryResponseWriterWrapperUnwraps(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	wrappers, unwraps := map[string]string{}, map[string]bool{}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return perr
		}
		pkg := f.Name.Name
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					for _, field := range st.Fields.List {
						if sel, ok := field.Type.(*ast.SelectorExpr); ok && len(field.Names) == 0 &&
							sel.Sel.Name == "ResponseWriter" {
							rel, _ := filepath.Rel(root, p)
							wrappers[pkg+"."+ts.Name.Name] = rel
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil || d.Name.Name != "Unwrap" || len(d.Recv.List) == 0 {
					continue
				}
				recv := d.Recv.List[0].Type
				if star, ok := recv.(*ast.StarExpr); ok {
					recv = star.X
				}
				if id, ok := recv.(*ast.Ident); ok {
					unwraps[pkg+"."+id.Name] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(wrappers) < 3 {
		t.Fatalf("only %d ResponseWriter wrappers found under %s; reading the tree wrong", len(wrappers), root)
	}
	for name, file := range wrappers {
		if !unwraps[name] {
			t.Errorf("%s (%s) embeds an http.ResponseWriter and has no Unwrap, so a websocket "+
				"upgrade behind it is answered 501", name, file)
		}
	}
}
