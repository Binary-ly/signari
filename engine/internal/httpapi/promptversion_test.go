package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Terms changed while somebody was reading them (5.13): their answer is to the
// version they were shown, so it is refused and the new text shown; answering
// that signs them in, and only the answer to what they read is recorded.
func TestAnAnswerToTermsChangedWhileReadingIsRefused(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	var promptID, slug string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.prompts (org_id, slug, title, body, fields, once, enabled)
		VALUES ($1::uuid, 'terms-'||substr(gen_random_uuid()::text,1,8), 'Terms', 'The first terms.',
		        '[{"name":"agree","type":"checkbox","label":"I agree","required":true}]'::jsonb, true, true)
		RETURNING id::text, slug`, f.orgID).Scan(&promptID, &slug); err != nil {
		t.Fatal(err)
	}

	clearSignInBucket(t, f.pool)
	page := f.postLogin(t, nil)
	if !strings.Contains(page.Body.String(), `name="version" value="1"`) {
		t.Fatalf("the prompt does not carry the version shown: %s", truncate(page.Body.String(), 300))
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.prompts SET body = 'The second terms.' WHERE id = $1::uuid`,
		promptID); err != nil {
		t.Fatal(err)
	}

	// The pending sign-in is the cookie the password step set; a re-shown
	// prompt does not set another.
	held := cookieFrom(page, PendingCookieName)
	if held == nil {
		t.Fatal("the password step set no pending sign-in")
	}
	answer := func(page *httptest.ResponseRecorder, version string) *httptest.ResponseRecorder {
		t.Helper()
		m := csrfValue.FindStringSubmatch(page.Body.String())
		if m == nil {
			t.Fatal("no CSRF token on the prompt")
		}
		form := url.Values{"prompt": {slug}, "version": {version}, "agree": {"on"}, csrfFormField: {m[1]}}
		r := httptest.NewRequest(http.MethodPost, "/login/prompt", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(held)
		r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		return rec
	}

	stale := answer(page, "1")
	if c := cookieFrom(stale, SessionCookieName); c != nil && c.Value != "" {
		t.Fatal("an answer to the terms as they were before the edit signed somebody in")
	}
	if !strings.Contains(stale.Body.String(), "changed while you were reading") ||
		!strings.Contains(stale.Body.String(), "The second terms.") ||
		!strings.Contains(stale.Body.String(), `name="version" value="2"`) {
		t.Fatalf("the new terms were not shown in place of the stale answer: %s", truncate(stale.Body.String(), 400))
	}
	if c := cookieFrom(answer(stale, "2"), SessionCookieName); c == nil || c.Value == "" {
		t.Fatal("answering the terms as they now are did not sign in")
	}
	var rows, current int
	if err := f.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE prompt_version = 2)
		FROM core.prompt_responses WHERE prompt_id = $1::uuid AND user_id = $2::uuid`,
		promptID, f.userID).Scan(&rows, &current); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || current != 1 {
		t.Errorf("recorded %d answer(s), %d to version 2; want only the answer to what was read", rows, current)
	}
}
