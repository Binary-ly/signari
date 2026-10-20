package httpapi

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// accountWritesExempt are the /account routes that change something and are
// not held to the re-authentication window, each with its reason.
var accountWritesExempt = map[string]string{
	"/account/requests": "answering a backchannel request decides what a client the person " +
		"uses may do, as the consent screen does, which no window holds; it changes nothing " +
		"about how the account signs in, and the approval is held to the client's own acr " +
		"and floor",
}

// Every route under /account that is not a GET calls credentialChangeRefused
// in its handler (4.04). Read from the router, so a new route is covered the
// day it is added: the password, ending sessions and revoking an
// application were open to any live session while the sign-in methods were
// held to a recent sign-in.
func TestEveryAccountWriteRequiresRecentAuth(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	bodies := map[string]*ast.BlockStmt{}
	var routes []*ast.CallExpr
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
				bodies[fn.Name.Name] = fn.Body
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok &&
					(sel.Sel.Name == "HandleFunc" || sel.Sel.Name == "Handle") && len(call.Args) == 2 {
					routes = append(routes, call)
				}
			}
			return true
		})
	}

	calls := func(body *ast.BlockStmt, name string) bool {
		found := false
		ast.Inspect(body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
					found = true
				}
			}
			return !found
		})
		return found
	}

	checked := 0
	for _, call := range routes {
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		pattern, _ := strconv.Unquote(lit.Value)
		method, path := "", pattern
		if i := strings.IndexByte(pattern, ' '); i > 0 {
			method, path = pattern[:i], strings.TrimSpace(pattern[i+1:])
		}
		if !strings.HasPrefix(path, "/account") || method == http.MethodGet {
			continue
		}
		if _, ok := accountWritesExempt[path]; ok {
			continue
		}
		checked++
		sel, ok := call.Args[1].(*ast.SelectorExpr)
		if !ok {
			t.Errorf("%s: the handler is not a method this test can read; name it, or teach the test",
				pattern)
			continue
		}
		body := bodies[sel.Sel.Name]
		if body == nil {
			t.Errorf("%s: no handler %s in the package", pattern, sel.Sel.Name)
			continue
		}
		if !calls(body, "credentialChangeRefused") {
			t.Errorf("%s (%s) changes the account and does not ask for a recent sign-in "+
				"(credentialChangeRefused), or say why in accountWritesExempt", pattern, sel.Sel.Name)
		}
	}
	if checked < 10 {
		t.Fatalf("found %d /account write routes; the scan is broken, not the code", checked)
	}
}

// The window is the organisation's: an hour-old sign-in is sent to sign in
// again under the ten-minute default, and is let through once the window is
// two hours.
func TestTheReauthWindowIsTheOrganisations(t *testing.T) {
	f, cookie := enrolFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE core.sessions SET auth_time = now() - interval '1 hour'
		WHERE cookie_hash = $1`, store.HashToken(cookie)); err != nil {
		t.Fatal(err)
	}
	revoke := func() *httptest.ResponseRecorder {
		return f.formPost(t, cookie, "/account/sessions", "/account/sessions/revoke",
			url.Values{"sid": {"not-a-session"}})
	}
	if rec := revoke(); rec.Header().Get("Location") != parkLogin("/account/sessions") {
		t.Fatalf("an hour-old sign-in under the default window got %d %q, want to sign in again",
			rec.Code, rec.Header().Get("Location"))
	}

	set := func(d time.Duration) {
		t.Helper()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := store.SetReauthWindow(ctx, tx, f.orgID, d); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	set(2 * time.Hour)
	if rec := revoke(); rec.Header().Get("Location") == parkLogin("/account/sessions") {
		t.Error("an hour-old sign-in under a two-hour window was sent to sign in again")
	}

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, bad := range []time.Duration{30 * time.Second, 25 * time.Hour, 90*time.Second + time.Millisecond} {
		if _, err := store.SetReauthWindow(ctx, tx, f.orgID, bad); err == nil {
			t.Errorf("a window of %s was accepted", bad)
		}
	}
}
