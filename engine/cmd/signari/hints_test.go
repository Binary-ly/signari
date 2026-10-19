package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Every command this CLI tells an operator to run exists.
//
// Its messages are full of instructions ("run `signari radius add-client`",
// "set it with `signari outpost search-group`"), and docs/cli.md is held to the
// dispatch by docsync while these were held to nothing. One named a command
// that did not exist (2.16), so the operator following the advice got the
// usage text, which looks exactly like a typo of their own.
func TestEveryCommandTheCLINamesExists(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}

	// What the dispatch answers: the cases of every `switch cmd`, and every
	// `cmd == "..."` the early dispatch tests.
	dispatched := map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SwitchStmt:
				if id, ok := x.Tag.(*ast.Ident); ok && id.Name == "cmd" {
					for _, s := range x.Body.List {
						for _, e := range s.(*ast.CaseClause).List {
							if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
								v, _ := strconv.Unquote(lit.Value)
								dispatched[v] = true
							}
						}
					}
				}
			case *ast.BinaryExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == "cmd" && x.Op == token.EQL {
					if lit, ok := x.Y.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						v, _ := strconv.Unquote(lit.Value)
						dispatched[v] = true
					}
				}
			}
			return true
		})
	}
	if len(dispatched) < 100 {
		t.Fatalf("found only %d dispatched commands; this test is reading the wrong thing", len(dispatched))
	}

	named := regexp.MustCompile(`\bsignari ([a-z][a-z0-9-]*)(?: ([a-z][a-z0-9-]*))?`)
	var missing []string
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for _, m := range named.FindAllStringSubmatch(s, -1) {
				cmd := m[1]
				if twoWordCommands[m[1]] {
					if m[2] == "" {
						continue // the group itself, as in "signari outpost"
					}
					cmd = m[1] + " " + m[2]
				}
				if !dispatched[cmd] {
					missing = append(missing, fset.Position(lit.Pos()).String()+": signari "+cmd)
				}
			}
			return true
		})
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("%s is named to the operator and is not a command", m)
	}
}
