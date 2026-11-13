package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/prompts"
	"signari.dev/engine/internal/store"
)

// An account made before an attribute was required is asked for it at sign-in, before
// any session (5.05): only the required ones the person may write, refused in the
// reader's language when left blank, written as their profile writes them, and not
// asked again once given.
func TestARequiredAttributeAPersonLacksIsAskedAtSignIn(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetRootKey(root)
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, a := range []store.Attribute{
		{Name: "team", DisplayName: "Team", ValueType: "string", UserReadable: true, UserWritable: true, Required: true},
		{Name: "remote", DisplayName: "Works remotely", ValueType: "boolean", UserReadable: true, UserWritable: true, Required: true},
		// Required, and an administrator's to fill: not asked.
		{Name: "badge", ValueType: "string", UserReadable: true, Required: true},
		// The person's to write, and not required: not asked.
		{Name: "nickname", ValueType: "string", UserReadable: true, UserWritable: true},
	} {
		if _, err := store.DeclareAttribute(ctx, tx, f.orgID, a); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	clearSignInBucket(t, f.pool)
	page := f.postLogin(t, nil)
	body := page.Body.String()
	if c := cookieFrom(page, SessionCookieName); c != nil && c.Value != "" {
		t.Fatal("a session was made before the missing attributes were given")
	}
	switch {
	case !strings.Contains(body, `name="prompt" value="`+prompts.RequiredAttributesSlug+`"`):
		t.Fatalf("no prompt for the missing attributes: %s", truncate(body, 400))
	case !strings.Contains(body, `name="team"`) || !strings.Contains(body, `name="remote"`):
		t.Fatalf("a missing attribute the person may write was not asked: %s", truncate(body, 600))
	case strings.Contains(body, `name="badge"`) || strings.Contains(body, `name="nickname"`):
		t.Fatal("an attribute the person may not write, or one not required, was asked")
	}
	m := csrfValue.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("the prompt carries no CSRF field")
	}
	answer := func(lang string, form url.Values) *httptest.ResponseRecorder {
		form.Set("prompt", prompts.RequiredAttributesSlug)
		form.Set(csrfFormField, m[1])
		r := httptest.NewRequest(http.MethodPost, "/login/prompt", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Accept-Language", lang)
		r.AddCookie(cookieFrom(page, PendingCookieName))
		r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		return rec
	}

	// Blank, from an Arabic browser: refused in Arabic, naming the field, no session.
	refused := answer("ar", url.Values{"team": {" "}})
	if c := cookieFrom(refused, SessionCookieName); c != nil && c.Value != "" {
		t.Fatal("a blank required attribute signed somebody in")
	}
	if !strings.Contains(refused.Body.String(), "الحقل «Team» مطلوب.") {
		t.Errorf("the refusal is not in Arabic naming the field: %s", truncate(refused.Body.String(), 600))
	}

	// Given, with an administrator's attribute slipped into the form.
	done := answer("en", url.Values{"team": {"Blue"}, "badge": {"forged"}})
	if c := cookieFrom(done, SessionCookieName); c == nil || c.Value == "" {
		t.Fatalf("giving the attributes did not sign in: %d %s", done.Code, truncate(done.Body.String(), 400))
	}
	held := heldAttributes(t, f.pool, f.userID, f.orgID, root)
	if held["team"] != "Blue" || held["remote"] != "false" || held["badge"] != "" {
		t.Errorf("held after sign-in: %v", held)
	}
	var audited int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE subject_id = $1::uuid
		AND event_type = 'user.attributes_updated' AND detail->>'by' = 'sign-in'`, f.userID).Scan(&audited); err != nil || audited != 1 {
		t.Errorf("%d sign-in attribute records (%v), want 1", audited, err)
	}

	// The next sign-in has nothing missing, and is not held.
	clearSignInBucket(t, f.pool)
	again := f.postLogin(t, nil)
	if strings.Contains(again.Body.String(), prompts.RequiredAttributesSlug) {
		t.Error("asked again for attributes already given")
	}
}

// No operator's prompt may take the slug sign-in asks with.
func TestTheRequiredAttributesSlugIsReserved(t *testing.T) {
	p := prompts.Prompt{Slug: prompts.RequiredAttributesSlug, Title: "Terms",
		Fields: []prompts.Field{{Name: "ok", Type: prompts.Checkbox, Label: "I agree"}}}
	if err := p.Validate(); err == nil {
		t.Fatal("an operator's prompt took the reserved slug")
	}
}
