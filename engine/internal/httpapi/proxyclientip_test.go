package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/clientip"
)

// Behind a proxy every request arrives from the proxy's address. Before the
// resolver, twenty wrong passwords from one client used up the budget of every
// client behind the same ingress.
func TestBehindATrustedProxyOneClientsFailuresDoNotLockOutAnother(t *testing.T) {
	f := newSignInFixture(t)
	clearOfWindowEdge(t, signInPerIPWindow)

	// Not httptest's default 192.0.2.1, which other tests sign in from: if the
	// resolver ever stops working, these failures land on the proxy's own
	// bucket, and on that address they would lock out every other test for five
	// minutes and report the damage somewhere unrelated. It did, once.
	const proxy = "192.0.2.213"
	ips, err := clientip.Parse("x-forwarded-for", proxy)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetClientIPResolver(ips)

	// Addresses no other test uses, so the buckets start empty.
	n := time.Now().UnixNano()
	a := fmt.Sprintf("198.18.%d.%d", n%250, (n/250)%250+1)
	b := fmt.Sprintf("198.19.%d.%d", n%250, (n/250)%250+1)

	attempt := func(peer, forwardedFor, username, password string) *httptest.ResponseRecorder {
		t.Helper()
		get := httptest.NewRequest(http.MethodGet, "/login", nil)
		get.RemoteAddr = peer + ":443"
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
		req.RemoteAddr = peer + ":443"
		if forwardedFor != "" {
			req.Header.Set("X-Forwarded-For", forwardedFor)
		}
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec
	}

	// A fresh identifier each time, so only the per-address budget is spent.
	for i := 0; i < signInPerIPLimit; i++ {
		attempt(proxy, a, fmt.Sprintf("nobody-%d-%d@example.test", n, i), "wrong")
	}
	if rec := attempt(proxy, a, fmt.Sprintf("nobody-%d-x@example.test", n), "wrong"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("client A's %dth failure through the proxy gave %d, want 429: the budget is not "+
			"per client", signInPerIPLimit+1, rec.Code)
	}

	if rec := attempt(proxy, b, f.email, signInTestPassword); rec.Code == http.StatusTooManyRequests {
		t.Fatal("client B, behind the same proxy, was locked out by client A's failures")
	} else if !strings.Contains(rec.Body.String(), "signed in") {
		t.Fatalf("client B's correct password gave %d: %.200s", rec.Code, rec.Body.String())
	}

	// A header from anyone but the proxy is not believed: naming A from
	// elsewhere is answered by the real peer, whose budget is untouched.
	elsewhere := fmt.Sprintf("198.20.%d.%d", n%250, (n/250)%250+1)
	if rec := attempt(elsewhere, a, f.email, signInTestPassword); rec.Code == http.StatusTooManyRequests {
		t.Fatal("a caller that is not the proxy was charged to the address its header named")
	}
}
