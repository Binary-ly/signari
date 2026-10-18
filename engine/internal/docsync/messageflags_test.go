package docsync

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every flag an error message asks for is one the CLI defines.
//
// TestEveryDocumentedFlagExists reads the docs. The messages a command prints
// when an argument is missing are the other place a reader is told what to
// type, and they had drifted three times: `idp add-issuer` asked for -jwks
// (the flag is -jwks-url), and `group create` and `group member` asked for
// -name and -email (they read -group and -email-member). Each was found by
// typing what the message said and being refused by the flag parser, which is
// the moment somebody who is already stuck is told to do something impossible.
//
// The shape it reads is the house one: "give -flag", with any list of flags
// after it ("give -org, -name and -email", "give both -tls-cert and -tls-key").
func TestEveryFlagAMessageAsksForExists(t *testing.T) {
	root := repoRoot(t)
	defined := cliFlags(t, root)

	literal := regexp.MustCompile("\"(?:[^\"\\\\\\n]|\\\\.)*\"|`[^`]*`")
	// From "give" to the end of the clause: a full stop, colon, semicolon or
	// the end of the string.
	clause := regexp.MustCompile(`\bgive\b([^.:;]*)`)
	flag := regexp.MustCompile(`(?:^|[\s,(])-([a-z][a-z0-9-]*)`)

	var undefined []string
	seen := 0
	err := filepath.Walk(filepath.Join(root, "engine"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return err
		}
		src := readRaw(t, path)
		rel, _ := filepath.Rel(root, path)
		for _, lit := range literal.FindAllStringIndex(src, -1) {
			text := src[lit[0]:lit[1]]
			for _, c := range clause.FindAllStringSubmatch(text, -1) {
				for _, f := range flag.FindAllStringSubmatch(c[1], -1) {
					seen++
					if !defined[f[1]] {
						line := strings.Count(src[:lit[0]], "\n") + 1
						undefined = append(undefined,
							rel+":"+itoa(line)+": asks for -"+f[1]+" in "+text)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 100 {
		t.Fatalf("only %d flags found in 'give ...' messages; the pattern has stopped matching", seen)
	}
	sort.Strings(undefined)
	for _, u := range undefined {
		t.Errorf("a message names a flag the CLI does not define:\n  %s", u)
	}
}

// And the flag it asks for is one that command reads.
//
// The first test cannot see the `group` drift: -name and -email are real flags,
// read by other commands, so "give -org and -name" passed while `group create
// -name x` set the display name and failed with the same message again. So
// this one follows each flag from its definition in run() to the functions it
// is passed to, and requires a message inside such a function to name one of
// the flags that function was given.
func TestEveryFlagAMessageAsksForIsOneTheCommandReads(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "engine", "cmd", "signari")
	fset := token.NewFileSet()
	var files []*ast.File
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if perr != nil {
			t.Fatal(perr)
		}
		files = append(files, f)
	}

	// x := fs.String("flag", ...) -> x is "flag".
	flagOf := map[string]string{}
	funcs := map[string]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
				funcs[fd.Name.Name] = fd
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			id, ok := as.Lhs[0].(*ast.Ident)
			call, ok2 := as.Rhs[0].(*ast.CallExpr)
			if !ok || !ok2 || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "fs" {
				return true
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				flagOf[id.Name] = strings.Trim(lit.Value, "\"")
			}
			return true
		})
	}
	if len(flagOf) < 50 {
		t.Fatalf("only %d flag variables found; the definition walk is wrong", len(flagOf))
	}

	// Every call passing *x hands that function x's flag.
	passed := map[string]map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			if !ok || funcs[fn.Name] == nil {
				return true
			}
			for _, a := range call.Args {
				if st, ok := a.(*ast.StarExpr); ok {
					if id, ok := st.X.(*ast.Ident); ok && flagOf[id.Name] != "" {
						if passed[fn.Name] == nil {
							passed[fn.Name] = map[string]bool{}
						}
						passed[fn.Name][flagOf[id.Name]] = true
					}
				}
			}
			return true
		})
	}
	if len(passed) < 50 {
		t.Fatalf("only %d functions receive flags; the call walk is wrong", len(passed))
	}

	clause := regexp.MustCompile(`\bgive\b([^.:;]*)`)
	flag := regexp.MustCompile(`(?:^|[\s,(])-([a-z][a-z0-9-]*)`)
	defined := cliFlags(t, root)
	var wrong []string
	for name, fd := range funcs {
		given := passed[name]
		if given == nil || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			for _, c := range clause.FindAllStringSubmatch(lit.Value, -1) {
				for _, m := range flag.FindAllStringSubmatch(c[1], -1) {
					if defined[m[1]] && !given[m[1]] {
						wrong = append(wrong, fmt.Sprintf("%s: %s asks for -%s, which it is "+
							"not given: %s", fset.Position(lit.Pos()), name, m[1], lit.Value))
					}
				}
			}
			return true
		})
	}
	sort.Strings(wrong)
	for _, w := range wrong {
		t.Errorf("%s", w)
	}
}
