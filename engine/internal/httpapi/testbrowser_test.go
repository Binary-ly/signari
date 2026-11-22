package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// testBrowser keeps every cookie a real browser would, in the order a response
// sets them, deletions included: what a test of the sign-in cookies is about is
// often what is left in the browser afterwards, across several of them.
type testBrowser struct {
	t    *testing.T
	h    http.Handler
	addr string
	jar  map[string]*http.Cookie
}

func newTestBrowser(t *testing.T, h http.Handler) *testBrowser {
	return &testBrowser{t: t, h: h, addr: uniqueTestAddr(t) + ":5555", jar: map[string]*http.Cookie{}}
}

func (b *testBrowser) do(r *http.Request) *httptest.ResponseRecorder {
	b.t.Helper()
	for _, c := range b.jar {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	r.RemoteAddr = b.addr
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, r)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.jar, c.Name)
		} else {
			b.jar[c.Name] = c
		}
	}
	return rec
}

func (b *testBrowser) get(path string) *httptest.ResponseRecorder {
	b.t.Helper()
	return b.do(httptest.NewRequest(http.MethodGet, path, nil))
}

// post submits form on page, with page's CSRF token.
func (b *testBrowser) post(path string, page *httptest.ResponseRecorder, form url.Values) *httptest.ResponseRecorder {
	b.t.Helper()
	m := csrfValue.FindStringSubmatch(page.Body.String())
	if m == nil {
		b.t.Fatalf("no CSRF token on the page before %s: %d %s", path, page.Code, truncate(page.Body.String(), 300))
	}
	form.Set(csrfFormField, m[1])
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(r)
}

// follow GETs a redirect's target.
func (b *testBrowser) follow(rec *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	b.t.Helper()
	loc := rec.Header().Get("Location")
	if loc == "" {
		b.t.Fatalf("no redirect to follow: %d %s", rec.Code, truncate(rec.Body.String(), 300))
	}
	return b.get(loc)
}

func (b *testBrowser) value(name string) string {
	if c, ok := b.jar[name]; ok {
		return c.Value
	}
	return ""
}
