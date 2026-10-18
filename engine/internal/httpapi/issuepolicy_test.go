package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// Guard 0.08d: everything that issues a token or an assertion has asked the
// access policy on the way.
//
// WS-Federation and SAML once issued with no policy check at all, and the
// device and CIBA approvals were found the same way: each new issuing path was
// written from the protocol's own specification, and an operator's deny rule
// is not in any of them. So this follows the code, not the protocols. An
// issuing function is one that mints through mintSet, builds an access token's
// claims or an ID token, or builds a SAML response. It passes when it calls
// checkAccessPolicy (or checkAccessPolicyIn) itself, or when every function in
// this package that calls it does, transitively. A route handler is called by
// nobody here, so the check has to be in it or below it.
//
// issuesWithoutAPolicyCheck is the list that may only shrink: an issuing path
// that does not ask, and why that is right.
var issuesWithoutAPolicyCheck = map[string]string{
	"mintTokens": "redeems an authorization code, which /authorize issued only after " +
		"asking the policy (flow.go, before consent); a code lives for a minute and " +
		"the refresh grant asks again",
	"issueDeviceTokens": "redeems a device or CIBA request the person approved, and the " +
		"approval asked the policy (device.go, ciba.go); the refresh grant asks again",
	"handleClientCredentialsGrant": "no person: the policy's conditions are about who " +
		"is signing in (groups, factors, networks, travel), so a catch-all rule would " +
		"refuse every machine client; a client is stopped by disabling it",
}

// askingFunctions are what count as asking the policy: the check itself, and
// the helper the non-interactive grants share.
var askingFunctions = map[string]bool{
	"checkAccessPolicy": true, "checkAccessPolicyIn": true, "grantRefusedByPolicy": true,
	// grantRefusedByPolicy for a person, the organisation check for a client.
	"txnSubjectRefused": true,
}

// tokenClaimTypes are the claim sets whose literal means a token is being
// issued: access tokens, and transaction tokens, which a review found issued
// with no check because this guard counted only the first.
var tokenClaimTypes = map[string]bool{"tokens.AccessTokenClaims": true, "txntoken.Claims": true}

func TestEveryIssuingPathAsksTheAccessPolicy(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	funcs := map[string]*ast.FuncDecl{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, e.Name(), nil, 0)
		if perr != nil {
			t.Fatal(perr)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				funcs[fd.Name.Name] = fd
			}
		}
	}

	issues := map[string]bool{}
	asks := map[string]bool{}
	callers := map[string]map[string]bool{}
	for name, fd := range funcs {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				if sel, ok := x.Type.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok && tokenClaimTypes[pkg.Name+"."+sel.Sel.Name] {
						issues[name] = true
					}
				}
			case *ast.CallExpr:
				var callee string
				switch fn := x.Fun.(type) {
				case *ast.SelectorExpr:
					callee = fn.Sel.Name
					if pkg, ok := fn.X.(*ast.Ident); ok &&
						(pkg.Name == "saml" && callee == "BuildResponse" ||
							pkg.Name == "txntoken" && callee == "Replace") {
						issues[name] = true
					}
				case *ast.Ident:
					callee = fn.Name
				}
				switch {
				case callee == "mintSet", callee == "SignIDToken":
					issues[name] = true
				case askingFunctions[callee]:
					asks[name] = true
				}
				if funcs[callee] != nil && callee != name {
					if callers[callee] == nil {
						callers[callee] = map[string]bool{}
					}
					callers[callee][name] = true
				}
			}
			return true
		})
	}
	if len(issues) < 5 || len(asks) < 5 {
		t.Fatalf("found %d issuing and %d asking functions; the walk is not reading the package",
			len(issues), len(asks))
	}

	// covered: this function asks, or every caller of it is covered.
	memo := map[string]bool{}
	visiting := map[string]bool{}
	var covered func(string) bool
	covered = func(name string) bool {
		if v, ok := memo[name]; ok {
			return v
		}
		if asks[name] {
			memo[name] = true
			return true
		}
		if visiting[name] || len(callers[name]) == 0 {
			return false
		}
		visiting[name] = true
		ok := true
		for c := range callers[name] {
			if !covered(c) && issuesWithoutAPolicyCheck[c] == "" {
				ok = false
			}
		}
		visiting[name] = false
		memo[name] = ok
		return ok
	}

	// Report each path into an issuing function that arrives without a check:
	// the function and the uncovered caller it is reached from, which is where
	// the question belongs.
	var unasked []string
	for name := range issues {
		if covered(name) || issuesWithoutAPolicyCheck[name] != "" {
			continue
		}
		if len(callers[name]) == 0 {
			unasked = append(unasked, name)
			continue
		}
		for c := range callers[name] {
			if !covered(c) && issuesWithoutAPolicyCheck[c] == "" {
				unasked = append(unasked, c+" -> "+name)
			}
		}
	}
	sort.Strings(unasked)
	unasked = compactStrings(unasked)
	for _, u := range unasked {
		t.Errorf("%s issues a token or an assertion and asks the access policy nowhere "+
			"on the way: an operator's deny rule does not apply to it. Ask, or list the "+
			"caller in issuesWithoutAPolicyCheck with why that is right", u)
	}
	for name := range issuesWithoutAPolicyCheck {
		if funcs[name] == nil {
			t.Errorf("issuesWithoutAPolicyCheck names %s, which no longer exists", name)
		}
	}
}

func compactStrings(in []string) []string {
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}
