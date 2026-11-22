package internal_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Every loop over a query's rows asks the rows for their error afterwards
// (0.31).
//
// pgx reports a query that failed, or failed partway, through rows.Err()
// after the loop, not from Query: the loop simply ends early. A function that
// never asks takes a failed read for an empty or a short one. The deployment
// read behind `plan` and `export org` did exactly that (0.30): a plan diffed
// against part of the state, an export would have written part of an
// organisation. Ten more were found when this looked: among them the sign-in
// flows a tenant configured, which a failed read would have replaced with the
// default flow, and the applications a front-channel logout tells.
//
// Read off the source, over every package: a `for X.Next()` loop in a
// function with no `X.Err()` call anywhere in it.
func TestEveryLoopOverRowsAsksForTheirError(t *testing.T) {
	fset := token.NewFileSet()
	var missing []string
	loops := 0
	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			nexts, errs := map[string]token.Pos{}, map[string]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.ForStmt:
					if name, ok := methodOnIdent(x.Cond, "Next"); ok {
						nexts[name] = x.Pos()
					}
				case *ast.CallExpr:
					if name, ok := methodOnIdent(x, "Err"); ok {
						errs[name] = true
					}
				}
				return true
			})
			for name, pos := range nexts {
				loops++
				if !errs[name] {
					missing = append(missing, fset.Position(pos).String()+" "+fn.Name.Name+" ("+name+")")
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if loops < 100 {
		t.Fatalf("only %d loops over rows found; the scan has gone blind", loops)
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("%s loops over rows and never asks %s for its error: a query that failed is "+
			"taken for an empty or a short result. Check it after the loop and return it",
			m, m[strings.LastIndex(m, "(")+1:len(m)-1]+".Err()")
	}
}

// methodOnIdent reports whether e is a call of ident.method(), and the ident.
func methodOnIdent(e ast.Expr, method string) (string, bool) {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	return id.Name, true
}
