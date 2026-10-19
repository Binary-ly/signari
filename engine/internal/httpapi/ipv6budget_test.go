package httpapi

import (
	"fmt"
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
	"time"
)

// A host on an IPv6 /64 can use any of its addresses, so a budget keyed by the
// full address was no budget: twenty failed passwords, then the next address
// along, twenty more. The budget is the /64's.
func TestOneIPv6SubnetSharesOneSignInBudget(t *testing.T) {
	f := newSignInFixture(t)
	clearOfWindowEdge(t, signInPerIPWindow)

	// A /64 no other test uses, so its bucket starts empty.
	n := time.Now().UnixNano()
	subnet := fmt.Sprintf("2001:db8:%x:%x", n%0xffff, (n/0xffff)%0xffff)
	attempt := func(addr, username, password string) *httptest.ResponseRecorder {
		t.Helper()
		peer := "[" + addr + "]:443"
		get := httptest.NewRequest(http.MethodGet, "/login", nil)
		get.RemoteAddr = peer
		grec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(grec, get)
		var cookie string
		for _, c := range grec.Result().Cookies() {
			if c.Name == CSRFCookieName {
				cookie = c.Value
			}
		}
		const marker = `name="` + csrfFormField + `" value="`
		body := grec.Body.String()
		i := strings.Index(body, marker)
		if i < 0 {
			t.Fatalf("the sign-in form carries no CSRF field: %d", grec.Code)
		}
		rest := body[i+len(marker):]
		form := url.Values{"username": {username}, "password": {password},
			csrfFormField: {rest[:strings.Index(rest, `"`)]}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: cookie})
		req.RemoteAddr = peer
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec
	}

	// Each failure from a different address in the /64, and a fresh
	// identifier each time, so only the per-address budget is spent.
	for i := 0; i < signInPerIPLimit; i++ {
		attempt(fmt.Sprintf("%s::%x", subnet, i+1), fmt.Sprintf("nobody-%d-%d@example.test", n, i), "wrong")
	}
	if rec := attempt(subnet+"::ffff", fmt.Sprintf("nobody-%d-x@example.test", n), "wrong"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the next address in the same /64 gave %d after %d failures from its "+
			"neighbours, want 429: the budget resets by changing address", rec.Code, signInPerIPLimit)
	}
	// The neighbouring /64 is another network, and is not charged.
	neighbour := fmt.Sprintf("2001:db8:%x:%x::1", n%0xffff, ((n/0xffff)+1)%0xffff)
	if rec := attempt(neighbour, f.email, signInTestPassword); rec.Code == http.StatusTooManyRequests {
		t.Fatal("a different /64 was locked out by its neighbour's failures")
	} else if !strings.Contains(rec.Body.String(), "signed in") {
		t.Fatalf("the neighbouring /64's correct password gave %d: %.200s", rec.Code, rec.Body.String())
	}
}

// Every budget keyed by an address is built through budgetIP, so no budget can
// be reset by stepping along a subnet, and a key's count and check agree. Read
// off the source: a string literal ending in ":ip:" joined to anything else
// is a budget keyed by the raw address.
func TestEveryAddressBudgetIsKeyedByItsSubnet(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var keys int
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			bin, ok := n.(*ast.BinaryExpr)
			if !ok || bin.Op != token.ADD {
				return true
			}
			lit, ok := bin.X.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING || !strings.HasSuffix(strings.Trim(lit.Value, "\"`"), ":ip:") {
				return true
			}
			keys++
			if call, ok := bin.Y.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "budgetIP" {
					return true
				}
			}
			t.Errorf("%s: %s is joined to the raw address; build the key with budgetIP, or an "+
				"IPv6 client resets this budget by changing address", fset.Position(lit.Pos()), lit.Value)
			return true
		})
	}
	if keys < 10 {
		t.Fatalf("found %d address-keyed budgets; the walk is not reading the package", keys)
	}
}
