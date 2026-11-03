package httpapi

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// A pushed request as a person meets it, who is usually not signed in. Every test of this
// feature stopped at the first page or signed in first, so a handle that the first page
// spent looked single-use and nobody noticed nobody could sign in with one.

// push pushes the fixture's authorization request, with extra parameters, and answers
// the handle.
func (f *signInFixture) push(t *testing.T, extra url.Values) string {
	t.Helper()
	form, err := url.ParseQuery(f.plainAuthz())
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range extra {
		form[name] = values
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	var out struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.RequestURI == "" {
		t.Fatalf("the push answered %d %s", rec.Code, rec.Body)
	}
	// The type as it was sent: Result() holds the header at WriteHeader, where
	// rec.Header() goes on showing what was set after it, which nothing received.
	if rec.Code != http.StatusCreated || rec.Result().Header.Get("Content-Type") != "application/json" {
		t.Fatalf("the push answered %d as %q", rec.Code, rec.Result().Header.Get("Content-Type"))
	}
	return out.RequestURI
}

// byHandle is a browser arriving at the authorization endpoint with a handle.
func (f *signInFixture) byHandle(t *testing.T, cookie, handle string) *httptest.ResponseRecorder {
	t.Helper()
	q := url.Values{"client_id": {f.clientID}, "request_uri": {handle}}
	req := httptest.NewRequest(http.MethodGet, oidc.PathAuthorize+"?"+q.Encode(), nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec
}

// signInThrough posts the sign-in form a page rendered, and follows where it sends the
// browser, as a browser would.
func (f *signInFixture) signInThrough(t *testing.T, page *httptest.ResponseRecorder) (*httptest.ResponseRecorder, string) {
	t.Helper()
	body := page.Body.String()
	hidden := regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)"`).FindAllStringSubmatch(body, -1)
	if len(hidden) == 0 {
		t.Fatalf("no form on the page: %d %.300s", page.Code, body)
	}
	form := url.Values{"username": {f.email}, "password": {signInTestPassword}}
	for _, m := range hidden {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range page.Result().Cookies() {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("signing in answered %d: %.300s", rec.Code, rec.Body)
	}
	cookie := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName {
			cookie = c.Value
		}
	}
	next := httptest.NewRequest(http.MethodGet, rec.Header().Get("Location"), nil)
	next.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	out := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(out, next)
	return out, cookie
}

func TestAPersonSignsInThroughAPushedRequest(t *testing.T) {
	f := newSignInFixture(t)
	handle := f.push(t, nil)

	// Software fetching a link to see what is there, and a person's reload, are not
	// an authorization: FAPI 2.0 §5.3.2.2 NOTE 3, "at the point of authorization, not at
	// the point of loading an authorization page".
	f.byHandle(t, "", handle)
	page := f.byHandle(t, "", handle)
	if !strings.Contains(page.Body.String(), `name="password"`) {
		t.Fatalf("the sign-in page, loaded twice: %d %.300s", page.Code, page.Body)
	}

	back, cookie := f.signInThrough(t, page)
	q := redirected(t, back)
	if q.Get("code") == "" {
		t.Fatalf("after signing in the client got %v", q)
	}
	if body := f.redeemPlain(t, back); body["access_token"] == nil {
		t.Errorf("the code redeemed to %v", body)
	}

	// Spent by the code. A second use is refused, and is not a second authorization.
	again := f.byHandle(t, cookie, handle)
	if strings.Contains(again.Header().Get("Location"), "code=") || !strings.Contains(again.Body.String(), "already been used") {
		t.Errorf("the handle used again: %d %q %.200s", again.Code, again.Header().Get("Location"), again.Body)
	}
}

// Two tabs on one handle, or a page raced: one code.
func TestAPushedRequestGivesOneCode(t *testing.T) {
	f := newSignInFixture(t)
	cookie := f.signInAndReturnCookie(t)
	handle := f.push(t, nil)
	sum := pushedHash(handle)
	ctx := context.Background()

	// One authorization has spent it in a transaction not yet committed.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if spent, err := store.SpendPushedRequest(ctx, tx, sum); err != nil || !spent {
		t.Fatalf("the first spend: %v, %v", spent, err)
	}
	// The other reads the handle as unspent, the first not having committed, and has
	// to wait at the row: an answer before the commit is a code nothing stopped.
	second := make(chan *httptest.ResponseRecorder, 1)
	go func() { second <- f.byHandle(t, cookie, handle) }()
	select {
	case rec := <-second:
		t.Fatalf("the second authorization did not wait: %d %q", rec.Code, rec.Header().Get("Location"))
	case <-time.After(300 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if rec := <-second; strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Errorf("a handle spent by another authorization gave a code: %q", rec.Header().Get("Location"))
	}
	if spent, err := func() (bool, error) {
		t2, err := f.pool.Begin(ctx)
		if err != nil {
			return false, err
		}
		defer func() { _ = t2.Rollback(ctx) }()
		return store.SpendPushedRequest(ctx, t2, sum)
	}(); err != nil || spent {
		t.Errorf("spending it again: %v, %v", spent, err)
	}
}

// A prompt in a pushed request is answered where the request is kept. It is not in the
// browser's query to be taken out, so prompt=login once went round for ever.
func TestAPromptInAPushedRequestIsAnsweredOnce(t *testing.T) {
	f := newSignInFixture(t)
	cookie := f.signInAndReturnCookie(t)
	handle := f.push(t, url.Values{"prompt": {"login"}})

	page := f.byHandle(t, cookie, handle)
	if !strings.Contains(page.Body.String(), `name="password"`) {
		t.Fatalf("prompt=login with somebody signed in: %d %.300s", page.Code, page.Body)
	}
	back, _ := f.signInThrough(t, page)
	if q := redirected(t, back); q.Get("code") == "" {
		t.Errorf("after signing in again the client got %v", q)
	}

	// Answering one leaves the other: a client asking for both wants both.
	both := f.push(t, url.Values{"prompt": {"login consent"}})
	f.signInThrough(t, f.byHandle(t, cookie, both))
	var left string
	if err := f.pool.QueryRow(context.Background(), `SELECT COALESCE(params->'prompt'->>0, '')
		FROM core.pushed_requests WHERE uri_hash = $1`, pushedHash(both)).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != "consent" {
		t.Errorf("after signing in the request still prompts for %q, want consent", left)
	}
}

// What a page shows or asks for is read from the pushed request, and what the browser can
// edit cannot change what is authorized: a hint is a hint.
func TestAPushedRequestsHintsReachTheSignInPage(t *testing.T) {
	f := newSignInFixture(t)
	handle := f.push(t, url.Values{"login_hint": {"ada@corp.example"}})
	if body := f.byHandle(t, "", handle).Body.String(); !strings.Contains(body, `value="ada@corp.example"`) {
		t.Errorf("the hint did not reach the box: %.600s", body)
	}

	q := url.Values{"client_id": {f.clientID}, "request_uri": {handle}, "scope": {"openid admin"},
		"redirect_uri": {"https://evil.test/cb"}}
	req := httptest.NewRequest(http.MethodGet, oidc.PathAuthorize+"?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "evil.test") || strings.Contains(rec.Body.String(), "admin") {
		t.Errorf("what the browser added reached the page: %.600s", rec.Body)
	}
}

// Refusing a pushed request goes back to the client it was pushed for: the redirect URI is
// in the row, and the query the consent form carries has only the handle.
func TestDenyingAPushedRequestTellsTheClient(t *testing.T) {
	f := newSignInFixture(t)
	cookie := f.signInAndReturnCookie(t)
	handle := f.push(t, nil)
	q := url.Values{"client_id": {f.clientID}, "request_uri": {handle}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	f.srv.errorToClient(rec, req, q.Encode(), "access_denied", "the user refused the request")
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://rp.test/cb") || !strings.Contains(loc, "error=access_denied") {
		t.Errorf("the client was told %d %q %.200s", rec.Code, loc, rec.Body)
	}
}
