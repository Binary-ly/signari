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
	"strings"
	"testing"
)

// A disabled client is refused on the next request at every endpoint it can
// call (ADR-007), not only at /authorize and the code redemption.
func TestADisabledClientIsRefusedEverywhere(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET client_type = 'confidential',
		client_secret_hash = $2,
		grant_types = ARRAY['authorization_code','refresh_token','client_credentials',
		                    'urn:ietf:params:oauth:grant-type:device_code']
		WHERE client_id = $1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	refresh := f.firstRefreshTokenWithSecret(t, secret)

	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET enabled = false WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	authed := func(form url.Values) url.Values {
		form.Set("client_id", f.clientID)
		form.Set("client_secret", secret)
		return form
	}
	call := func(path string, form url.Values) (int, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	for _, c := range []struct {
		name, path string
		form       url.Values
	}{
		{"client_credentials", "/oauth2/token", url.Values{"grant_type": {"client_credentials"}}},
		{"refresh_token", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}},
		{"pushed authorization", "/oauth2/par", url.Values{"response_type": {"code"},
			"redirect_uri": {"https://rp.test/cb"}, "scope": {"openid"},
			"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}},
		{"device authorization", "/oauth2/device_authorization", url.Values{"scope": {"openid"}}},
		{"revocation", "/oauth2/revoke", url.Values{"token": {refresh}}},
		{"introspection", "/oauth2/introspect", url.Values{"token": {refresh}}},
	} {
		code, body := call(c.path, authed(c.form))
		if code < 400 {
			t.Errorf("%s from a disabled client answered %d: %s", c.name, code, truncate(body, 160))
		}
	}
}

// lookupsThatAdmitADisabledClient are the calls that load a client whatever
// its state, each with why that is safe. Every other load goes through
// lookupClient, which refuses a disabled one.
var lookupsThatAdmitADisabledClient = map[string]string{
	"flow.go lookupClient":               "the choke point itself, which refuses what this returns disabled",
	"flow.go lookupClientAnyState":       "the loader the declared callers share",
	"flow.go handleAuthorize":            "oauth.ValidateAuthz refuses a disabled client first, telling the person why",
	"accounts.go errorToClient":          "oauth.ValidateAuthz again, before any redirect to the client",
	"account.go loginOrg":                "only which organisation's sign-in page to show; nothing is granted",
	"connected.go handleConnectedRevoke": "the person removing the application, which reads its token lifetime to say when its tokens stop",
}

// Derived from the source: a handler that loads a client any other way than
// through lookupClient can serve a disabled one, which is how eleven endpoints
// did until October 2026 while three checked for themselves.
func TestEveryClientLookupThatAdmitsADisabledClientIsDeclared(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, _ := sel.X.(*ast.Ident)
				anyState := sel.Sel.Name == "lookupClientAnyState" ||
					(sel.Sel.Name == "Lookup" && pkg != nil && pkg.Name == "clients")
				if !anyState {
					return true
				}
				where := path + " " + fn.Name.Name
				seen[where] = true
				if _, ok := lookupsThatAdmitADisabledClient[where]; !ok {
					t.Errorf("%s (%s) loads a client in any state; use lookupClient, which "+
						"refuses a disabled one, or declare why this one may not",
						where, fset.Position(call.Pos()))
				}
				return true
			})
		}
	}
	for where := range lookupsThatAdmitADisabledClient {
		if !seen[where] {
			t.Errorf("%s is declared and loads no client any more; remove it", where)
		}
	}
}

// firstRefreshTokenWithSecret is firstRefreshToken for a confidential fixture.
func (f *tokenFixture) firstRefreshTokenWithSecret(t *testing.T, secret string) string {
	t.Helper()
	verifier := strings.Repeat("d", 48)
	code := f.issueCodeWithScopes(t, verifier, []string{"openid", "offline_access"})
	status, body := f.post(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://rp.test/cb"}, "client_id": {f.clientID},
		"client_secret": {secret}, "code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("code exchange failed: %d %v", status, body)
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("no refresh token in %v", body)
	}
	return rt
}
