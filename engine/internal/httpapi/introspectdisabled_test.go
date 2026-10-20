package httpapi

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A token is only as good as the client it was issued to (ADR-007): disabling
// the client must turn its outstanding tokens inactive at the next
// introspection, not when they expire. The resource server is the caller,
// because the disabled client can no longer authenticate to ask (2.50).
func TestIntrospectionAnswersInactiveForADisabledClientsToken(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	rsID := "https://" + f.clientID + "-rs.example.test"
	rsSecret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, grant_types, scopes, require_pkce)
		VALUES ($1,$2,'RS','confidential',$3, ARRAY['client_credentials'],
		        ARRAY['openid'], true)`, rsID, f.orgID, hash); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, rsID)
	})

	const verifier = "verifier-for-introspection-disabled-0123456789"
	code := f.issueCodeForResource(t, verifier, rsID)
	status, body := f.post(t, f.redeem(code, verifier))
	if status != http.StatusOK {
		t.Fatalf("redemption: %d %v", status, body)
	}
	access, _ := body["access_token"].(string)

	introspect := func() map[string]any {
		t.Helper()
		form := url.Values{"token": {access}}
		req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(url.QueryEscape(rsID), url.QueryEscape(rsSecret)) // RFC 6749 §2.3.1
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var b map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &b)
		return b
	}

	if got := introspect(); got["active"] != true {
		t.Fatalf("before disabling, the resource server was told %v", got)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE core.clients SET enabled = false WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	if got := introspect(); got["active"] != false {
		t.Errorf("a disabled client's access token introspected as active: %v", got)
	}
}

// A token with no session behind it -- jwt-bearer mints these -- has nothing
// that ends when its person is deactivated, so the person is read too. And
// userinfo, which reads the person already, refuses a disabled client's token.
func TestASessionlessTokenEndsWithItsPersonAndUserinfoWithItsClient(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	mint := func(sid string, scopes ...string) string {
		t.Helper()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		c, err := f.srv.lookupClient(ctx, f.clientID)
		if err != nil {
			t.Fatal(err)
		}
		resp, _, err := f.srv.mintSet(ctx, tx, c, f.orgID, f.userID, sid, "", scopes, nil, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return resp.AccessToken
	}
	// Sessionless, so `openid` is out: an ID token needs a session to describe.
	access := mint("", "profile")
	ownerSecret := revocableClient(t, f)

	if got := f.introspect(t, access, f.clientID, ownerSecret); got["active"] != true {
		t.Fatalf("before deactivating, the token introspected as %v", got)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	if got := f.introspect(t, access, f.clientID, ownerSecret); got["active"] != false {
		t.Errorf("a deactivated person's sessionless token introspected as active: %v", got)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE core.users SET status = 'active' WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}

	// Userinfo wants `openid`, so this token has a session, which disabling the
	// client leaves running.
	access = mint(f.sid, "openid")
	userinfo := func() int {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+access)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code
	}
	if got := userinfo(); got != http.StatusOK {
		t.Fatalf("before disabling, userinfo gave %d", got)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE core.clients SET enabled = false WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	if got := userinfo(); got != http.StatusUnauthorized {
		t.Errorf("userinfo answered a disabled client's token with %d, want 401", got)
	}
}

// Every place that accepts an access token reads its holder. Found by the
// direction the failure travels: a new acceptance site is a new call to
// tokens.VerifyAccessTokenAny, so each call's claims variable must reach a
// store.TokenHolderLive call as `<claims>.ClientID, <claims>.Subject` in the
// same function. The revocation endpoint is the one exemption: it ends the
// token rather than honouring it.
func TestEveryPlaceThatAcceptsAnAccessTokenReadsItsHolder(t *testing.T) {
	exempt := map[string]string{
		"handleRevoke": "revocation ends the token; it does not act on its authority",
	}
	var files []string
	for _, root := range []string{"..", "../../cmd"} {
		if err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				files = append(files, p)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	sites := 0
	for _, p := range files {
		if strings.Contains(p, "/tokens/") {
			continue // where it is defined
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			checked := map[string]bool{}
			var verified []string
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.AssignStmt:
					if len(n.Rhs) == 1 && isCall(n.Rhs[0], "tokens", "VerifyAccessTokenAny") {
						if id, ok := n.Lhs[0].(*ast.Ident); ok {
							verified = append(verified, id.Name)
						}
					}
				case *ast.CallExpr:
					if isCall(n, "store", "TokenHolderLive") && len(n.Args) == 4 &&
						isField(n.Args[2], "ClientID") == isField(n.Args[3], "Subject") {
						if v := isField(n.Args[2], "ClientID"); v != "" {
							checked[v] = true
						}
					}
				}
				return true
			})
			for _, v := range verified {
				sites++
				if _, ok := exempt[fn.Name.Name]; ok {
					continue
				}
				if !checked[v] {
					t.Errorf("%s: %s accepts an access token as %q and never passes %s.ClientID "+
						"and %s.Subject to store.TokenHolderLive, so a disabled client's or a "+
						"deactivated person's token is honoured there until it expires",
						p, fn.Name.Name, v, v, v)
				}
			}
		}
	}
	if sites < 7 {
		t.Fatalf("found %d calls to tokens.VerifyAccessTokenAny; there were 7 when this "+
			"was written, so this test is no longer finding them", sites)
	}
}

func isCall(e ast.Expr, pkg, name string) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == pkg && sel.Sel.Name == name
}

// isField returns v when e is `v.<field>`, and "" otherwise.
func isField(e ast.Expr, field string) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != field {
		return ""
	}
	if x, ok := sel.X.(*ast.Ident); ok {
		return x.Name
	}
	return ""
}
