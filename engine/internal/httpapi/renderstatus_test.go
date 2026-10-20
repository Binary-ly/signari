package httpapi

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"signari.dev/engine/internal/oauth"
)

// No handler writes a status and then renders a page.
//
// Headers set after WriteHeader are dropped without a word, and renderPage sets
// every header a page needs: the policy, with the brand's img-src when a logo
// is configured, and no-store. Six handlers wrote their status first. Five
// sent a policy of their own with no img-src, so the operator's logo was
// blocked on the second-factor page and on every error page; the UMA claims
// error page sent no policy and no cache header at all, and
// TestEveryHTMLResponseCarriesAPolicyAndNoStore could not see it, because it
// set no Content-Type by hand. renderPageStatus writes the status after the
// headers.
func TestNoPageIsRenderedAfterItsStatusIsWritten(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			var status token.Pos
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "WriteHeader":
					if !status.IsValid() {
						status = call.Pos()
					}
				case "renderPage":
					checked++
					if status.IsValid() && status < call.Pos() {
						t.Errorf("%s: %s writes its status at line %d and then renders a page, "+
							"whose headers are then dropped; use renderPageStatus",
							fset.Position(call.Pos()), fn.Name.Name, fset.Position(status).Line)
					}
				}
				return true
			})
		}
	}
	if checked == 0 {
		t.Fatal("found no renderPage call at all; the scan is broken, not the code")
	}
}

// The six pages, rendered for an instance with a logo: each answers with its
// status and with the headers renderPage sets, the logo's img-src among them.
func TestTheErrorAndCodePagesCarryTheBrandsPolicy(t *testing.T) {
	j := newPasskeyJourney(t)
	ctx := context.Background()
	if _, err := j.pool.Exec(ctx, `
		INSERT INTO core.brands (instance_id, logo_url)
		SELECT id, 'https://cdn.example.test/logo.svg' FROM core.instances WHERE issuer = $1
		ON CONFLICT (instance_id) DO UPDATE SET logo_url = EXCLUDED.logo_url`,
		j.srv.cfg.Issuer); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = j.pool.Exec(context.Background(), `DELETE FROM core.brands
			WHERE instance_id = (SELECT id FROM core.instances WHERE issuer = $1)`, j.srv.cfg.Issuer)
	})

	s := j.srv
	pages := map[string]struct {
		status int
		render func(w http.ResponseWriter, r *http.Request)
	}{
		"mfa": {http.StatusUnauthorized, func(w http.ResponseWriter, r *http.Request) {
			s.renderMFA(w, r, j.userID, "", "That code is not valid.")
		}},
		"err": {http.StatusBadRequest, func(w http.ResponseWriter, r *http.Request) {
			s.writeAuthzError(w, r, oauth.AuthzRequest{}, &oauth.AuthzError{
				Code: "invalid_request", Description: "probe", Disposition: oauth.DispositionDirect})
		}},
		"federr (federation)": {http.StatusBadRequest, func(w http.ResponseWriter, r *http.Request) {
			s.federationError(w, r, "probe")
		}},
		"federr (authorization)": {http.StatusBadRequest, func(w http.ResponseWriter, r *http.Request) {
			s.renderAuthzFailure(w, r, "probe")
		}},
		"samlerr": {http.StatusBadRequest, func(w http.ResponseWriter, r *http.Request) {
			s.samlRefuse(w, r, "probe")
		}},
		"umaclaimserr": {http.StatusBadRequest, func(w http.ResponseWriter, r *http.Request) {
			s.renderClaimsError(w, r, "probe", "probe")
		}},
	}
	for name, p := range pages {
		rec := httptest.NewRecorder()
		p.render(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		// Result's headers, not the recorder's: the recorder's map keeps
		// what was set after the status, which no browser ever receives.
		sent := rec.Result().Header
		csp := sent.Get("Content-Security-Policy")
		if rec.Code != p.status {
			t.Errorf("%s: answered %d, want %d", name, rec.Code, p.status)
		}
		if !strings.Contains(csp, "img-src https:") {
			t.Errorf("%s: the policy blocks the configured logo: %q", name, csp)
		}
		if sent.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store", name, sent.Get("Cache-Control"))
		}
	}
}
