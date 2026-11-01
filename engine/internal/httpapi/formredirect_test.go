package httpapi

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"signari.dev/engine/internal/oidc"
)

var (
	loginAuthz    = regexp.MustCompile(`name="authz" value="([^"]*)"`)
	refreshTarget = regexp.MustCompile(`content="0;url=([^"]+)"`)
)

func ownForm(r *http.Request) *http.Request {
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Sec-Fetch-Dest", "document")
	return r
}

func redirectingTo(target string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "kept", Value: "1"})
		http.Redirect(w, r, target, http.StatusSeeOther)
	})
}

// What a browser enforces is not something an HTTP client can see, so this pins
// the response that gets past it: interop/form-redirect-e2e.mjs is the proof, in
// a real browser, that this response is the right one.
func TestARedirectAfterOurOwnFormIsAPage(t *testing.T) {
	f := newSignInFixture(t)
	target := `https://rp.test/cb?code=a&state=b"c'd<e`
	r := ownForm(httptest.NewRequest(http.MethodPost, "/login", nil))
	rec := httptest.NewRecorder()
	f.srv.withFormRedirects(redirectingTo(target)).ServeHTTP(rec, r)

	if rec.Code != http.StatusOK || rec.Header().Get("Location") != "" {
		t.Fatalf("still a redirect: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if cookieFrom(rec, "kept") == nil {
		t.Error("a cookie set with the redirect was lost")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control %q on a page holding an authorization code", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'none'") ||
		!strings.Contains(got, "form-action 'none'") {
		t.Errorf("the page says %q", got)
	}
	body := rec.Body.String()
	want := "https://rp.test/cb?code=a&amp;state=b&#34;c&#39;d&lt;e"
	if !strings.Contains(body, `content="0;url=`+want+`"`) || !strings.Contains(body, `<a href="`+want+`">`) {
		t.Errorf("the page does not go there, escaped: %s", body)
	}
}

func TestOnlyOurOwnFormsAreAnsweredWithAPage(t *testing.T) {
	f := newSignInFixture(t)
	for name, build := range map[string]func() *http.Request{
		// A link, or the browser following a redirect.
		"a navigation": func() *http.Request { return ownForm(httptest.NewRequest(http.MethodGet, "/x", nil)) },
		// An API client, and this repository's own tests.
		"no browser": func() *http.Request { return httptest.NewRequest(http.MethodPost, "/x", nil) },
		// A relying party's form: its policy, not ours.
		"another site's form": func() *http.Request {
			r := ownForm(httptest.NewRequest(http.MethodPost, oidc.PathAuthorize, nil))
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			return r
		},
		// The passkey ceremony's fetch, which reads the answer rather than following it.
		"a script": func() *http.Request {
			r := ownForm(httptest.NewRequest(http.MethodPost, "/x", nil))
			r.Header.Set("Sec-Fetch-Dest", "empty")
			return r
		},
		"a frame": func() *http.Request {
			r := ownForm(httptest.NewRequest(http.MethodPost, "/x", nil))
			r.Header.Set("Sec-Fetch-Dest", "iframe")
			return r
		},
	} {
		rec := httptest.NewRecorder()
		f.srv.withFormRedirects(redirectingTo("https://rp.test/cb")).ServeHTTP(rec, build())
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://rp.test/cb" {
			t.Errorf("%s answered %d %q", name, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestAnythingElseAFormIsAnsweredWithIsLeftAlone(t *testing.T) {
	f := newSignInFixture(t)
	for name, h := range map[string]http.Handler{
		"a page": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("the page"))
		}),
		"a refusal": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("the page"))
		}),
		// A Location that is not a redirect.
		"something created": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "/made")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("the page"))
		}),
		// Too late to be anything else: the status has gone.
		"a redirect after a page": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("the page"))
			http.Redirect(w, r, "https://rp.test/cb", http.StatusSeeOther)
		}),
	} {
		rec := httptest.NewRecorder()
		f.srv.withFormRedirects(h).ServeHTTP(rec, ownForm(httptest.NewRequest(http.MethodPost, "/x", nil)))
		if rec.Body.String() != "the page" {
			t.Errorf("%s answered %d %q", name, rec.Code, rec.Body.String())
		}
	}
}

// What a handler writes beside its redirect has no place on the page.
func TestABodySentWithARedirectIsDropped(t *testing.T) {
	f := newSignInFixture(t)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://rp.test/cb")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte("<a>moved</a>"))
	})
	rec := httptest.NewRecorder()
	f.srv.withFormRedirects(h).ServeHTTP(rec, ownForm(httptest.NewRequest(http.MethodPost, "/x", nil)))
	if strings.Contains(rec.Body.String(), "moved") {
		t.Errorf("the page carries the handler's body: %s", rec.Body.String())
	}
}

// The whole journey, through the routes as a server serves them: the form is
// answered with a page, and from there a person arrives with a code.
func TestASignInLeavesTheFormBeforeItLeavesTheOrigin(t *testing.T) {
	f := newSignInFixture(t)
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET first_party = true WHERE client_id = $1`,
		f.clientID); err != nil {
		t.Fatal(err)
	}
	h := f.srv.Routes()
	page := httptest.NewRecorder()
	h.ServeHTTP(page, httptest.NewRequest(http.MethodGet, oidc.PathAuthorize+"?"+f.plainAuthz(), nil))
	m := csrfValue.FindStringSubmatch(page.Body.String())
	authz := loginAuthz.FindStringSubmatch(page.Body.String())
	if m == nil || authz == nil {
		t.Fatalf("no sign-in form (%d): %.300s", page.Code, page.Body.String())
	}
	form := url.Values{"username": {f.email}, "password": {signInTestPassword}, csrfFormField: {m[1]},
		"authz": {html.UnescapeString(authz[1])}}
	r := ownForm(httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode())))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = testClientIP(t) + ":5555"
	r.AddCookie(cookieFrom(page, CSRFCookieName))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || rec.Header().Get("Location") != "" {
		t.Fatalf("the form was answered with a redirect a browser will stop: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	session := cookieFrom(rec, SessionCookieName)
	if session == nil {
		t.Fatalf("no session came with the page: %.300s", rec.Body.String())
	}
	next := refreshTarget.FindStringSubmatch(rec.Body.String())
	if next == nil {
		t.Fatalf("the page goes nowhere: %s", rec.Body.String())
	}

	onward := httptest.NewRequest(http.MethodGet, html.UnescapeString(next[1]), nil)
	onward.AddCookie(session)
	arrived := httptest.NewRecorder()
	h.ServeHTTP(arrived, onward)
	if !strings.HasPrefix(arrived.Header().Get("Location"), "https://rp.test/cb?code=") {
		t.Errorf("the page led to %d %q", arrived.Code, arrived.Header().Get("Location"))
	}
}
