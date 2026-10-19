package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The operator's token_issue provider is asked at every grant (2.03). It was
// asked at authorization_code redemption only, so its veto stopped a code and
// nothing else, refresh included. Derived from the grant dispatch in
// handleToken, so a grant added there without asking fails here by name.
func TestEveryGrantConsultsTheTokenHook(t *testing.T) {
	funcs := httpapiFuncs(t)
	consults := func(name string) bool { return reachesHook(funcs, name, 0, map[string]bool{}) }

	var grants []string
	ast.Inspect(funcs["handleToken"], func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		cond, ok := ifs.Cond.(*ast.BinaryExpr)
		if !ok || cond.Op != token.EQL {
			return true
		}
		if sel, ok := cond.X.(*ast.SelectorExpr); !ok || sel.Sel.Name != "GrantType" {
			return true
		}
		for _, callee := range called(ifs.Body) {
			if strings.HasPrefix(callee, "handle") && funcs[callee] != nil {
				grants = append(grants, callee)
				if !consults(callee) {
					t.Errorf("%s is dispatched for a grant and never asks the token_issue "+
						"provider, so a veto does not stop the tokens it issues", callee)
				}
			}
		}
		return true
	})
	if len(grants) < 8 {
		t.Fatalf("found %d grant handlers in handleToken's dispatch; there were nine when "+
			"this was written, so this test is no longer reading it", len(grants))
	}
	if !consults("handleToken") {
		t.Error("handleToken's own authorization_code redemption no longer asks the provider")
	}

	// Every mint: a function that calls mintSet asks, or every function that
	// calls it does. mintTokens is the second kind; issueDeviceTokens and
	// releaseCIBAPush, which no grant dispatches directly, are the first.
	callers := map[string][]string{}
	for name, fd := range funcs {
		for _, callee := range called(fd.Body) {
			callers[callee] = append(callers[callee], name)
		}
	}
	for _, minter := range callers["mintSet"] {
		if consults(minter) {
			continue
		}
		for _, up := range callers[minter] {
			if !consults(up) {
				t.Errorf("%s mints through %s without asking the token_issue provider", up, minter)
			}
		}
	}
}

// An access token is signed in one place, which carries what the provider
// contributed. They were dropped: filtered against the allow-list and then
// never put into any token.
func TestEveryAccessTokenIsSignedThroughOneHelper(t *testing.T) {
	signed := 0
	for name, fd := range httpapiFuncs(t) {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "SignJSON" || len(call.Args) == 0 {
				return true
			}
			lit, ok := call.Args[0].(*ast.CompositeLit)
			if !ok {
				if id, isID := call.Args[0].(*ast.Ident); isID && name == "signAccessToken" && id.Name == "c" {
					signed++
				}
				return true
			}
			if typ, ok := lit.Type.(*ast.SelectorExpr); ok && typ.Sel.Name == "AccessTokenClaims" {
				t.Errorf("%s signs an access token itself, so a token_issue provider's "+
					"claims never reach it; sign it with signAccessToken", name)
			}
			return true
		})
	}
	if signed != 1 {
		t.Fatalf("signAccessToken signs %d times; this test is no longer reading it", signed)
	}
}

// httpapiFuncs parses this package's non-test files: name to declaration.
func httpapiFuncs(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*ast.FuncDecl{}
	fset := token.NewFileSet()
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, p, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				out[fd.Name.Name] = fd
			}
		}
	}
	return out
}

// called names every function a node calls, by the name after any receiver or
// package.
func called(n ast.Node) []string {
	var out []string
	ast.Inspect(n, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				out = append(out, fun.Name)
			case *ast.SelectorExpr:
				out = append(out, fun.Sel.Name)
			}
		}
		return true
	})
	return out
}

// reachesHook reports whether a function asks the provider, itself or through
// what it calls in this package, a few calls deep.
func reachesHook(funcs map[string]*ast.FuncDecl, name string, depth int, seen map[string]bool) bool {
	fd := funcs[name]
	if fd == nil || seen[name] || depth > 4 {
		return false
	}
	seen[name] = true
	for _, callee := range called(fd.Body) {
		if callee == "consultTokenHook" || callee == "ConsultTokenProvider" {
			return true
		}
		if reachesHook(funcs, callee, depth+1, seen) {
			return true
		}
	}
	return false
}
