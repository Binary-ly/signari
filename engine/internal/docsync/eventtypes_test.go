package docsync

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"signari.dev/engine/internal/audit"
)

// The event types a subscription may name are the types the engine audits,
// because every audited event is published (audit.Write fans out). Three
// lists have to agree, and none of them can be written by hand without
// drifting (2.34):
//
//   - what the code audits: the Type of every audit.Event literal, read from
//     the source, with the audit package's constants resolved;
//   - audit.EventTypes, which `events subscribe` checks a name against, so a
//     typo such as login.failure is refused instead of subscribing to nothing;
//   - the catalogue in docs/events.md, which is how an operator finds a name.
//
// A type built at run time cannot be checked against anything, so it is
// refused here by position.
func TestEveryEventTypeIsRegisteredAndCatalogued(t *testing.T) {
	root := repoRoot(t)
	consts := map[string]string{}
	type site struct {
		lit *ast.CompositeLit
		fn  funcInDir
	}
	var literals []site
	var files []*ast.File
	var paths []string
	byDir := map[string][]funcInDir{}
	fset := token.NewFileSet()
	for _, dir := range []string{"engine/internal", "engine/cmd"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			files = append(files, f)
			paths = append(paths, path)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, f := range files {
		inAudit := strings.Contains(paths[i], "/internal/audit/")
		if inAudit {
			for _, d := range f.Decls {
				g, ok := d.(*ast.GenDecl)
				if !ok || g.Tok != token.CONST {
					continue
				}
				for _, s := range g.Specs {
					vs := s.(*ast.ValueSpec)
					for j, n := range vs.Names {
						if j < len(vs.Values) {
							if lit, ok := vs.Values[j].(*ast.BasicLit); ok && lit.Kind == token.STRING {
								consts[n.Name], _ = strconv.Unquote(lit.Value)
							}
						}
					}
				}
			}
		}
		dir := filepath.Dir(paths[i])
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			fn := funcInDir{decl: fd, dir: dir}
			byDir[dir] = append(byDir[dir], fn)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				cl, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				switch typ := cl.Type.(type) {
				case *ast.SelectorExpr:
					if x, ok := typ.X.(*ast.Ident); ok && x.Name == "audit" && typ.Sel.Name == "Event" {
						literals = append(literals, site{cl, fn})
					}
				case *ast.Ident:
					if inAudit && typ.Name == "Event" {
						literals = append(literals, site{cl, fn})
					}
				}
				return true
			})
		}
	}

	// resolve finds the literal values a name can hold where it is used: a
	// local set only from literals, or a parameter, by the arguments its
	// callers pass, a few calls deep. ok is false when any of them is not a
	// literal, which nothing here can check.
	var resolve func(name string, fn funcInDir, depth int) ([]string, bool)
	resolve = func(name string, fn funcInDir, depth int) ([]string, bool) {
		if s, ok := consts[name]; ok {
			return []string{s}, true
		}
		var vals []string
		ok, assigned := true, false
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			as, isAssign := n.(*ast.AssignStmt)
			if !isAssign {
				return true
			}
			for i, l := range as.Lhs {
				if id, isID := l.(*ast.Ident); isID && id.Name == name && i < len(as.Rhs) {
					assigned = true
					if lit, isLit := as.Rhs[i].(*ast.BasicLit); isLit && lit.Kind == token.STRING {
						v, _ := strconv.Unquote(lit.Value)
						vals = append(vals, v)
					} else {
						ok = false
					}
				}
			}
			return true
		})
		if assigned {
			return vals, ok
		}
		idx := paramIndex(fn.decl, name)
		if idx < 0 || depth > 3 {
			return nil, false
		}
		for _, caller := range byDir[fn.dir] {
			ast.Inspect(caller.decl.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall || idx >= len(call.Args) {
					return true
				}
				var callee string
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					callee = fun.Name
				case *ast.SelectorExpr:
					callee = fun.Sel.Name
				}
				if callee != fn.decl.Name.Name {
					return true
				}
				switch a := call.Args[idx].(type) {
				case *ast.BasicLit:
					v, _ := strconv.Unquote(a.Value)
					vals = append(vals, v)
				case *ast.Ident:
					sub, subOK := resolve(a.Name, caller, depth+1)
					vals, ok = append(vals, sub...), ok && subOK
				default:
					ok = false
				}
				return true
			})
		}
		return vals, ok && len(vals) > 0
	}

	used := map[string]bool{}
	for _, s := range literals {
		for _, e := range s.lit.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "Type" {
				continue
			}
			var vals []string
			resolved := true
			switch v := kv.Value.(type) {
			case *ast.BasicLit:
				str, _ := strconv.Unquote(v.Value)
				vals = []string{str}
			case *ast.SelectorExpr:
				str, ok := consts[v.Sel.Name]
				vals, resolved = []string{str}, ok
			case *ast.Ident:
				vals, resolved = resolve(v.Name, s.fn, 0)
			case *ast.BinaryExpr:
				// "ciba." + verb: a literal prefix and a name that resolves.
				prefix, isLit := v.X.(*ast.BasicLit)
				suffix, isID := v.Y.(*ast.Ident)
				if v.Op != token.ADD || !isLit || !isID {
					resolved = false
					break
				}
				p, _ := strconv.Unquote(prefix.Value)
				var tails []string
				tails, resolved = resolve(suffix.Name, s.fn, 0)
				for _, tail := range tails {
					vals = append(vals, p+tail)
				}
			default:
				resolved = false
			}
			if !resolved {
				t.Errorf("%s: an audit event's type here is built from something other than "+
					"literals, so it cannot be checked against the registry",
					fset.Position(kv.Value.Pos()))
			}
			for _, v := range vals {
				used[v] = true
			}
		}
	}
	if len(used) < 100 {
		t.Fatalf("found %d audited event types; there were over a hundred when this was written, "+
			"so this test is no longer finding them", len(used))
	}

	registered := map[string]bool{}
	for _, e := range audit.EventTypes {
		registered[e] = true
	}
	if !sort.StringsAreSorted(audit.EventTypes) {
		t.Error("audit.EventTypes is not sorted, which is how a duplicate hides")
	}
	for _, missing := range difference(used, registered) {
		t.Errorf("%s is audited and is not in audit.EventTypes, so `events subscribe` refuses it", missing)
	}
	for _, stale := range difference(registered, used) {
		t.Errorf("%s is in audit.EventTypes and nothing audits it, so a subscription to it "+
			"receives nothing", stale)
	}

	doc, err := os.ReadFile(filepath.Join(root, "docs", "events.md"))
	if err != nil {
		t.Fatal(err)
	}
	section := string(doc)
	start := strings.Index(section, "\n## Event catalogue")
	if start < 0 {
		t.Fatal("docs/events.md has no ## Event catalogue section")
	}
	section = section[start+1:]
	if end := strings.Index(section[3:], "\n## "); end >= 0 {
		section = section[:end+3]
	}
	catalogued := map[string]bool{}
	for _, m := range regexp.MustCompile("`([a-z0-9_]+\\.[a-z0-9_.]+)`").FindAllStringSubmatch(section, -1) {
		catalogued[m[1]] = true
	}
	for _, missing := range difference(registered, catalogued) {
		t.Errorf("%s is subscribable and docs/events.md's catalogue does not list it", missing)
	}
	for _, stale := range difference(catalogued, registered) {
		t.Errorf("docs/events.md's catalogue lists %s, which is not an event type", stale)
	}
}

// funcInDir is a function and the package directory it is in, which is where
// its callers are looked for.
type funcInDir struct {
	decl *ast.FuncDecl
	dir  string
}

// paramIndex is the position of a named parameter, or -1.
func paramIndex(fd *ast.FuncDecl, name string) int {
	i := 0
	for _, field := range fd.Type.Params.List {
		for _, n := range field.Names {
			if n.Name == name {
				return i
			}
			i++
		}
	}
	return -1
}

func difference(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
