package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A person chooses their language on the account page (5.20): it is saved on
// the account and in the browser, pages speak it whatever the browser asks for,
// an application's ui_locales still comes first, and signing in on another
// browser brings it along.
func TestAPersonChoosesTheirLanguage(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	clearSignInBucket(t, f.pool)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `UPDATE core.users SET locale = NULL WHERE id = $1::uuid`, f.userID)
	})
	signIn := func(b *testBrowser) {
		t.Helper()
		b.post("/login", b.get("/login"), url.Values{"username": {f.email}, "password": {signInTestPassword}})
		if b.value(SessionCookieName) == "" {
			t.Fatal("the fixture did not sign in")
		}
	}
	page := func(b *testBrowser, path, acceptLanguage string) string {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Accept-Language", acceptLanguage)
		return b.do(r).Body.String()
	}
	locale := func() string {
		t.Helper()
		var l *string
		if err := f.pool.QueryRow(ctx, `SELECT locale FROM core.users WHERE id = $1::uuid`, f.userID).Scan(&l); err != nil {
			t.Fatal(err)
		}
		if l == nil {
			return ""
		}
		return *l
	}

	b := newTestBrowser(t, f.srv.Routes())
	signIn(b)
	account := b.get("/account")
	if !strings.Contains(account.Body.String(), `action="/account/language"`) || !strings.Contains(account.Body.String(), "العربية") {
		t.Fatalf("the account page offers no language: %s", truncate(account.Body.String(), 300))
	}
	if rec := b.post("/account/language", account, url.Values{"language": {"xx"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("a language nobody has: %d, want 400", rec.Code)
	}
	b.post("/account/language", account, url.Values{"language": {"ar"}})
	if locale() != "ar" || b.value(LanguageCookieName) != "ar" {
		t.Fatalf("after choosing Arabic: saved %q, browser %q", locale(), b.value(LanguageCookieName))
	}
	if body := page(b, "/account", "en-GB,en;q=0.9"); !strings.Contains(body, "إدارة حسابك") {
		t.Error("the account page did not speak the chosen language over the browser's")
	}
	if body := page(b, "/login?ui_locales=en", "ar"); !strings.Contains(body, `lang="en"`) {
		t.Error("an application's ui_locales did not come first")
	}

	other := newTestBrowser(t, f.srv.Routes())
	signIn(other)
	if other.value(LanguageCookieName) != "ar" {
		t.Errorf("signing in on another browser did not bring the choice: %q", other.value(LanguageCookieName))
	}

	b.post("/account/language", b.get("/account"), url.Values{"language": {""}})
	if locale() != "" || b.value(LanguageCookieName) != "" {
		t.Errorf("after choosing the browser's setting: saved %q, browser %q", locale(), b.value(LanguageCookieName))
	}
	if body := page(b, "/account", "en"); !strings.Contains(body, "Manage your account") {
		t.Error("with no choice the page did not follow the browser")
	}
}
