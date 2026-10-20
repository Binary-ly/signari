package logging

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// bannedKeys name a person in a way somebody would recognise. The diagnostic
// log is collected, shipped and kept by whoever runs it, outside anything
// erasure reaches, so a line that must say whose request it was says so with
// the subject id, and the audit trail says the rest (3.07). LDAP binds and
// RADIUS logins logged the username they were given, valid or not.
var bannedKeys = map[string]bool{
	"username": true, "user_name": true, "email": true, "mail": true, "upn": true,
	"bound_dn": true, "user_dn": true, "display_name": true, "login_hint": true,
}

var logMethods = map[string]bool{
	"Debug": true, "Info": true, "Warn": true, "Error": true, "Log": true,
	"DebugContext": true, "InfoContext": true, "WarnContext": true, "ErrorContext": true,
}

// No log call in the engine names a person by a key above, or logs a
// certificate's subject, which is a person's name or address. Read from the
// source, every package, so a new call cannot opt out.
func TestNoLogLineNamesAPerson(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	calls := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || d.Name() == "vendor") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !logMethods[sel.Sel.Name] || !isLogger(sel.X) {
				return true
			}
			calls++
			for _, arg := range call.Args {
				where := fset.Position(arg.Pos())
				rel, _ := filepath.Rel(root, where.Filename)
				if key := literal(arg); bannedKeys[key] {
					found = append(found, rel+":"+strconv.Itoa(where.Line)+" logs "+strconv.Quote(key))
				}
				if inner, ok := arg.(*ast.CallExpr); ok {
					if isel, ok := inner.Fun.(*ast.SelectorExpr); ok && len(inner.Args) > 0 &&
						bannedKeys[literal(inner.Args[0])] {
						found = append(found, rel+":"+strconv.Itoa(where.Line)+" logs "+
							strconv.Quote(literal(inner.Args[0]))+" through "+isel.Sel.Name)
					}
				}
				if text := source(fset, arg); strings.Contains(text, ".Subject.String()") ||
					strings.Contains(text, ".EmailAddresses") {
					found = append(found, rel+":"+strconv.Itoa(where.Line)+" logs a certificate's "+text)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls < 300 {
		t.Fatalf("only %d log calls found under %s; this test is reading the tree wrong", calls, root)
	}
	if len(found) > 0 {
		t.Errorf("%d log line(s) name a person; log the subject id, or nothing, and let "+
			"the audit trail say who:\n  %s", len(found), strings.Join(found, "\n  "))
	}
}

// isLogger reports whether x is a logger: `log`, `s.log`, `a.logger`, `slog`.
func isLogger(x ast.Expr) bool {
	var name string
	switch v := x.(type) {
	case *ast.Ident:
		name = v.Name
	case *ast.SelectorExpr:
		name = v.Sel.Name
	default:
		return false
	}
	name = strings.ToLower(name)
	return name == "log" || name == "slog" || name == "logger" || strings.HasSuffix(name, "log") ||
		strings.HasSuffix(name, "logger")
}

func literal(e ast.Expr) string {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return s
}

func source(fset *token.FileSet, e ast.Expr) string {
	var b bytes.Buffer
	_ = printer.Fprint(&b, fset, e)
	return b.String()
}
