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

	"signari.dev/engine/internal/store"
)

// RP-initiated logout returns the browser to a post_logout_redirect_uri the
// client registered, with its state, and to nothing else. The table the URI is
// checked against had a reader and no writer, so every relying party that
// asked to be returned after sign-out was refused (2.11).
func TestRPInitiatedLogoutReturnsToARegisteredURI(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	h := f.srv.Routes()

	set := func(uris ...string) {
		t.Helper()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := store.SetClientLogout(ctx, tx, f.clientID, store.ClientLogout{PostLogoutRedirectURIs: &uris}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	action := regexp.MustCompile(`<form method="post" action="([^"]*)"`)
	csrf := regexp.MustCompile(`name="` + csrfFormField + `" value="([^"]*)"`)

	// Sign out through the confirmation the endpoint asks for, as a browser does.
	logout := func(target string) *httptest.ResponseRecorder {
		t.Helper()
		session := f.signInAndReturnCookie(t)
		q := url.Values{"post_logout_redirect_uri": {target}, "client_id": {f.clientID}, "state": {"s1"}}
		get := httptest.NewRequest(http.MethodGet, "/oauth2/logout?"+q.Encode(), nil)
		get.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
		page := httptest.NewRecorder()
		h.ServeHTTP(page, get)
		a, c := action.FindStringSubmatch(page.Body.String()), csrf.FindStringSubmatch(page.Body.String())
		if a == nil || c == nil {
			t.Fatalf("no confirmation form: %d %s", page.Code, page.Body)
		}
		post := httptest.NewRequest(http.MethodPost, html.UnescapeString(a[1]),
			strings.NewReader(url.Values{csrfFormField: {c[1]}}.Encode()))
		post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		post.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
		for _, ck := range page.Result().Cookies() {
			post.AddCookie(ck)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, post)
		return rec
	}

	if rec := logout("https://rp.test/bye"); rec.Code != http.StatusBadRequest {
		t.Errorf("before any registration the logout answered %d, want 400", rec.Code)
	}

	set("https://rp.test/bye")
	rec := logout("https://rp.test/bye")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://rp.test/bye?state=s1" {
		t.Fatalf("a registered post-logout URI answered %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := logout("https://rp.test/elsewhere"); rec.Code != http.StatusBadRequest {
		t.Errorf("an unregistered URI answered %d, want 400", rec.Code)
	}

	// Refused at registration rather than stored and never matched.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	bad := []string{"http://rp.test/plaintext"}
	if err := store.SetClientLogout(ctx, tx, f.clientID, store.ClientLogout{PostLogoutRedirectURIs: &bad}); err == nil {
		t.Error("a plaintext post-logout URI was accepted")
	}
}
