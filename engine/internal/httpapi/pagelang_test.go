package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// An operator's prompt answered with a required field left blank is told so in the
// reader's language, the field named as the operator labelled it. It was "please
// complete: Team" for everybody.
func TestAPromptLeftBlankIsSaidInTheReadersLanguage(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	var slug string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.prompts (org_id, slug, title, fields, once, enabled)
		VALUES ($1::uuid, 'team-'||substr(gen_random_uuid()::text,1,8), 'Your team',
		        '[{"name":"team","type":"select","label":"Team","options":["blue","green"],"required":true},
		          {"name":"desk","type":"text","label":"Desk","required":true}]'::jsonb,
		        true, true)
		RETURNING slug`, f.orgID).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.pool.Exec(context.Background(), `DELETE FROM core.prompts WHERE slug = $1`, slug) })

	clearSignInBucket(t, f.pool)
	page := f.postLogin(t, nil)
	m := csrfValue.FindStringSubmatch(page.Body.String())
	if m == nil || !strings.Contains(page.Body.String(), `name="team"`) {
		t.Fatalf("the prompt was not shown: %s", truncate(page.Body.String(), 300))
	}
	for lang, want := range map[string]string{
		"ar": "يُرجى إكمال: Team، Desk.",
		"en": "Please complete: Team, Desk.",
	} {
		form := url.Values{"prompt": {slug}, "version": {"1"}, "team": {""}, csrfFormField: {m[1]}}
		r := httptest.NewRequest(http.MethodPost, "/login/prompt", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Accept-Language", lang)
		r.AddCookie(cookieFrom(page, PendingCookieName))
		r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		if body := rec.Body.String(); !strings.Contains(body, want) {
			t.Errorf("%s: want %q in %s", lang, want, truncate(body, 600))
		}
	}
}

// The text-message enrolment page says why it cannot enrol in the reader's language.
func TestAnEnrolmentPageRefusesInTheReadersLanguage(t *testing.T) {
	f, cookie := enrolFixture(t)
	if f.srv.smsAvailable() {
		t.Skip("this server has a text-message gateway; the refusal checked here is for one without")
	}
	for lang, want := range map[string]string{
		"ar": "الرسائل النصية غير متاحة على هذا الخادم",
		"en": "Text messages are not available on this server. Ask an administrator",
	} {
		// The token from another account page: without a gateway this one shows
		// no form, which is the point.
		body := formPostIn(t, f, cookie, "/account/password", "/account/mfa/sms", lang,
			url.Values{"step": {"start"}, "number": {"+15550100"}})
		if !strings.Contains(body, want) {
			t.Errorf("%s: want %q in %s", lang, want, truncate(body, 600))
		}
	}
}
