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

	"signari.dev/engine/internal/store"
)

const browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

// A sign-out that has nowhere to send the browser ends on a page that says it is done
// (0.93). It ended on {"status":"signed out"}, read as raw JSON by a person in a
// browser. Anything that does not ask for HTML is still answered that JSON, so no
// script reading it is broken.
func TestASignOutEndsOnAPageForABrowserAndJSONForAnythingElse(t *testing.T) {
	f := newSignInFixture(t)
	h := f.srv.Routes()
	action := regexp.MustCompile(`<form method="post" action="([^"]*)"`)
	csrf := regexp.MustCompile(`name="` + csrfFormField + `" value="([^"]*)"`)

	// Signed in, then out through the confirmation the end-session endpoint asks for,
	// with no post_logout_redirect_uri, so the sign-out stops here.
	signOut := func(accept, language string) *httptest.ResponseRecorder {
		t.Helper()
		session := f.signInAndReturnCookie(t)
		get := httptest.NewRequest(http.MethodGet, "/oauth2/logout", nil)
		get.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
		page := httptest.NewRecorder()
		h.ServeHTTP(page, get)
		a, c := action.FindStringSubmatch(page.Body.String()), csrf.FindStringSubmatch(page.Body.String())
		if a == nil || c == nil {
			t.Fatalf("no confirmation form: %d %.300s", page.Code, page.Body)
		}
		post := httptest.NewRequest(http.MethodPost, html.UnescapeString(a[1]),
			strings.NewReader(url.Values{csrfFormField: {html.UnescapeString(c[1])}}.Encode()))
		post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if accept != "" {
			post.Header.Set("Accept", accept)
		}
		if language != "" {
			post.Header.Set("Accept-Language", language)
		}
		post.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
		for _, ck := range page.Result().Cookies() {
			post.AddCookie(ck)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, post)
		_, live, err := store.ResolveSessionCookie(context.Background(), f.pool, store.HashToken(session), f.srv.instanceID)
		if err != nil || live {
			t.Fatalf("the session outlived its sign-out (%d, %v)", rec.Code, err)
		}
		return rec
	}

	rec := signOut(browserAccept, "")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("a browser signing out was answered %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(body, "You are signed out") || !strings.Contains(body, `href="/login"`) ||
		strings.Contains(body, `"status"`) {
		t.Errorf("a browser signing out was not shown the page that says so: %.600s", body)
	}

	if body := signOut(browserAccept, "ar").Body.String(); !strings.Contains(body, "تم تسجيل خروجك") ||
		!strings.Contains(body, `dir="rtl"`) {
		t.Errorf("a browser asking for Arabic was not shown the Arabic page: %.600s", body)
	}

	for _, accept := range []string{"", "application/json"} {
		rec := signOut(accept, "")
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK ||
			len(got) != 1 || got["status"] != "signed out" {
			t.Errorf("Accept %q was answered %d %s, want the JSON it always was", accept, rec.Code, rec.Body)
		}
	}
}

// A SAML logout chain that comes back to nowhere shows the person which applications
// were told and which could not be reached, the one thing somebody leaving a shared
// computer needs to know; a caller asking for JSON is given the same two lists.
func TestTheSAMLChainsReportIsShownToTheBrowser(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	const told, unreached = "https://wiki.chain.test/sp", "https://analytics.chain.test/sp"

	// Two providers; the first could not be reached, the browser comes back from the
	// second.
	finish := func(accept string) *httptest.ResponseRecorder {
		t.Helper()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		token, err := store.BeginLogoutChain(ctx, tx, store.LogoutChain{OrgID: f.orgID, SID: "sid-signedout-test",
			UserID: f.userID, Remaining: []store.LogoutStep{{EntityID: unreached}, {EntityID: told}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, ok, err := store.AdvanceLogoutChain(ctx, tx, token, true); err != nil || !ok {
			t.Fatalf("advancing past the first provider: %v %v", ok, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, "/saml/slo", nil)
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		rec := httptest.NewRecorder()
		if !f.srv.continueSAMLLogoutChain(rec, r, token, false) {
			t.Fatal("the chain was not continued")
		}
		return rec
	}

	rec := finish(browserAccept)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("the end of the chain was answered %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	// The count is set apart as a number of its own (U+2068 ... U+2069), as every count
	// the pages show is, and so is each address.
	one := string(rune(0x2068)) + "1" + string(rune(0x2069))
	for _, want := range []string{
		one + " application was told you signed out:", "<li><bdi>" + told + "</bdi></li>",
		one + " application could not be reached, and your session there may still be open:",
		"<li><bdi>" + unreached + "</bdi></li>",
	} {
		if !strings.Contains(body, want) {
			_, content, _ := strings.Cut(body, "<main")
			t.Errorf("the page does not say %q: %.900s", want, content)
		}
	}

	var got struct {
		Status   string   `json:"status"`
		Notified []string `json:"notified"`
		Failed   []string `json:"failed"`
	}
	rec = finish("application/json")
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.Status != "signed out" ||
		len(got.Notified) != 1 || got.Notified[0] != told || len(got.Failed) != 1 || got.Failed[0] != unreached {
		t.Errorf("asked for JSON, the end of the chain answered %d %s", rec.Code, rec.Body)
	}
}

// A sign-out that could not end the session does not claim it did. The cookies are
// cleared before it is answered, so signing out again from that browser would find no
// session and report success: the page sends the person to their sessions to end it.
func TestASignOutThatFailedSaysSoAndDoesNotOfferAFalseRetry(t *testing.T) {
	srv := newSignInFixture(t).srv
	r := httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	r.Header.Set("Accept", browserAccept)
	rec := httptest.NewRecorder()
	srv.signOutFailed(rec, r)
	body := rec.Body.String()
	if rec.Code != http.StatusInternalServerError || !strings.Contains(body, "Sign-out did not finish") ||
		!strings.Contains(body, `href="/account/sessions"`) || strings.Contains(body, "You are signed out") ||
		strings.Contains(body, `href="/oauth2/logout"`) {
		t.Errorf("a failed sign-out shown to a browser: %d %.600s", rec.Code, body)
	}

	r = httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	rec = httptest.NewRecorder()
	srv.signOutFailed(rec, r)
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusInternalServerError ||
		got["error"] != "server_error" {
		t.Errorf("a failed sign-out answered to an API caller: %d %s", rec.Code, rec.Body)
	}
}
