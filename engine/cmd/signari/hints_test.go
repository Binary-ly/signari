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

// Every flag this CLI tells an operator to give exists.
//
// The same failure one level down: `authz set-model` refused with "-org and
// -file are both required" while its flag was -model-file, so the operator
// who did as told was told it again.
func TestEveryFlagTheCLINamesExists(t *testing.T) {
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

	// Defined: the name argument of every flag.FlagSet definition, whichever
	// FlagSet it is on.
	nameArg := map[string]int{
		"String": 0, "Bool": 0, "Int": 0, "Int64": 0, "Uint": 0, "Uint64": 0,
		"Float64": 0, "Duration": 0, "Func": 0, "BoolFunc": 0, "TextVar": 1,
		"StringVar": 1, "BoolVar": 1, "IntVar": 1, "Int64Var": 1, "UintVar": 1,
		"Float64Var": 1, "DurationVar": 1, "Var": 1,
	}
	defined := map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "slog" {
				return true
			}
			i, ok := nameArg[sel.Sel.Name]
			if !ok || len(call.Args) <= i {
				return true
			}
			if lit, ok := call.Args[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				v, _ := strconv.Unquote(lit.Value)
				defined[v] = true
			}
			return true
		})
	}
	if len(defined) < 100 {
		t.Fatalf("found only %d flags; this test is reading the wrong thing", len(defined))
	}

	named := regexp.MustCompile("(?:^|[\\s(`\"',])-([a-z][a-z0-9]*(?:-[a-z0-9]+)*)")
	// Flags of other programs the messages tell an operator to run, allowed
	// only where that program is named in the same message.
	others := map[string]string{"c": "head ", "e": "ipa-getkeytab ", "u": "date "}
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
				if prog, ok := others[m[1]]; ok && strings.Contains(s, prog) {
					continue
				}
				if !defined[m[1]] {
					missing = append(missing, fset.Position(lit.Pos()).String()+": -"+m[1])
				}
			}
			return true
		})
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("%s is named to the operator and is not a flag", m)
	}

	// And the one the command was given. `-file` exists, for `import
	// keycloak`; telling an operator running `authz set-model` to give it is
	// as wrong as naming a flag nobody defined. Each case of the dispatch
	// passes some flags' values (`*modelFile`) to the function it calls, and
	// every flag that function's messages name must be among them. A message
	// pointing at another command (`signari …`) is that command's business.
	varFlag := map[string]string{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			id, ok := as.Lhs[0].(*ast.Ident)
			call, ok2 := as.Rhs[0].(*ast.CallExpr)
			if !ok || !ok2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || nameArg[sel.Sel.Name] != 0 || len(call.Args) == 0 {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "fs" {
				return true
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				v, _ := strconv.Unquote(lit.Value)
				varFlag[id.Name] = v
			}
			return true
		})
	}
	funcs := map[string]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
				funcs[fd.Name.Name] = fd
			}
		}
	}
	given := map[string]map[string]bool{}    // function -> flags its callers pass
	cmdFlags := map[string]map[string]bool{} // command -> flags its branch passes
	// dispatch records one branch of the dispatch: the commands it answers and
	// the flags its body dereferences, per command and per function called.
	dispatch := func(labels []string, body ast.Node) {
		passed := map[string]bool{"dsn": true}
		for _, l := range labels {
			cmdFlags[l] = passed
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if st, ok := n.(*ast.StarExpr); ok {
				if id, ok := st.X.(*ast.Ident); ok && varFlag[id.Name] != "" {
					passed[varFlag[id.Name]] = true
				}
			}
			return true
		})
		ast.Inspect(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			if !ok || funcs[fn.Name] == nil || fn.Name == "usage" {
				return true
			}
			if given[fn.Name] == nil {
				given[fn.Name] = map[string]bool{"dsn": true}
			}
			for _, a := range call.Args {
				ast.Inspect(a, func(n ast.Node) bool {
					if st, ok := n.(*ast.StarExpr); ok {
						if id, ok := st.X.(*ast.Ident); ok && varFlag[id.Name] != "" {
							given[fn.Name][varFlag[id.Name]] = true
						}
					}
					return true
				})
			}
			return true
		})
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SwitchStmt:
				if id, ok := x.Tag.(*ast.Ident); !ok || id.Name != "cmd" {
					return true
				}
				for _, s := range x.Body.List {
					var labels []string
					for _, e := range s.(*ast.CaseClause).List {
						if lit, ok := e.(*ast.BasicLit); ok {
							v, _ := strconv.Unquote(lit.Value)
							labels = append(labels, v)
						}
					}
					dispatch(labels, s)
				}
			case *ast.IfStmt:
				// The early dispatch: `if cmd == "outpost run" { ... }`.
				be, ok := x.Cond.(*ast.BinaryExpr)
				if !ok || be.Op != token.EQL {
					return true
				}
				id, ok := be.X.(*ast.Ident)
				lit, ok2 := be.Y.(*ast.BasicLit)
				if !ok || !ok2 || id.Name != "cmd" {
					return true
				}
				v, _ := strconv.Unquote(lit.Value)
				dispatch([]string{v}, x.Body)
			}
			return true
		})
	}
	if len(given) < 100 {
		t.Fatalf("found only %d dispatched functions; this test is reading the wrong thing", len(given))
	}
	var wrong []string
	for name, own := range given {
		// A message may also name the flags of a command the same function
		// tells the operator to run, split across lines as such hints are.
		flags := map[string]bool{}
		for k := range own {
			flags[k] = true
		}
		ast.Inspect(funcs[name].Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, _ := strconv.Unquote(lit.Value)
			for _, m := range regexp.MustCompile(`\bsignari ([a-z][a-z0-9-]*)(?: ([a-z][a-z0-9-]*))?`).FindAllStringSubmatch(s, -1) {
				for _, c := range []string{m[1], m[1] + " " + m[2]} {
					for k := range cmdFlags[c] {
						flags[k] = true
					}
				}
			}
			return true
		})
		ast.Inspect(funcs[name].Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for _, m := range named.FindAllStringSubmatch(s, -1) {
				if prog, ok := others[m[1]]; ok && strings.Contains(s, prog) {
					continue
				}
				if defined[m[1]] && !flags[m[1]] {
					wrong = append(wrong, fset.Position(lit.Pos()).String()+": "+name+" names -"+m[1])
				}
			}
			return true
		})
	}
	sort.Strings(wrong)
	for _, m := range wrong {
		t.Errorf("%s, which the command it serves is not given", m)
	}
}
