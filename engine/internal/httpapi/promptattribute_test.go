package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// A prompt's answer written to an attribute (5.14), and released by a claim
// mapper from the next token on.
func TestAPromptAnswerBecomesAnAttributeAndAMappedClaim(t *testing.T) {
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
	attrID, err := store.DeclareAttribute(ctx, tx, f.orgID, store.Attribute{Name: "department", ValueType: "string"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.claim_mappers (org_id, attribute_id, claim_name, destination, required_scope)
		VALUES ($1::uuid, $2::uuid, 'department', 'id_token', 'openid')`, f.orgID, attrID); err != nil {
		t.Fatal(err)
	}
	var slug string
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.prompts (org_id, slug, title, fields, once, enabled)
		VALUES ($1::uuid, 'team-'||substr(gen_random_uuid()::text,1,8), 'Your team',
		        '[{"name":"team","type":"select","label":"Team","options":["engineering","finance"],"required":true,"attribute":"department"}]'::jsonb,
		        true, true)
		RETURNING slug`, f.orgID).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	clearSignInBucket(t, f.pool)
	page := f.postLogin(t, nil)
	m := csrfValue.FindStringSubmatch(page.Body.String())
	if m == nil || !strings.Contains(page.Body.String(), `name="team"`) {
		t.Fatalf("the prompt was not shown: %s", truncate(page.Body.String(), 300))
	}
	form := url.Values{"prompt": {slug}, "version": {"1"}, "team": {"finance"}, csrfFormField: {m[1]}}
	r := httptest.NewRequest(http.MethodPost, "/login/prompt", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookieFrom(page, PendingCookieName))
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	if c := cookieFrom(rec, SessionCookieName); c == nil || c.Value == "" {
		t.Fatalf("answering did not sign in: %d %s", rec.Code, truncate(rec.Body.String(), 300))
	}

	rtx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rtx.Rollback(ctx) }()
	claims, err := store.MappedClaims(ctx, rtx, f.userID, f.orgID, f.clientID, store.ClaimInIDToken, "openid", root)
	if err != nil {
		t.Fatal(err)
	}
	if claims["department"] != "finance" {
		t.Errorf("the mapped claims are %v, want department = finance from the prompt's answer", claims)
	}
}

// An answer its attribute's type refuses is said in the reader's language and names
// the field as the prompt labels it; nobody is signed in.
func TestAPromptAnswerTheAttributeRefusesIsSaidInTheReadersLanguage(t *testing.T) {
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
	if _, err := store.DeclareAttribute(ctx, tx, f.orgID, store.Attribute{Name: "age", ValueType: "number"}); err != nil {
		t.Fatal(err)
	}
	var slug string
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.prompts (org_id, slug, title, fields, once, enabled)
		VALUES ($1::uuid, 'age-'||substr(gen_random_uuid()::text,1,8), 'Your age',
		        '[{"name":"age","type":"text","label":"Age in years","required":true,"attribute":"age"}]'::jsonb,
		        true, true)
		RETURNING slug`, f.orgID).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	clearSignInBucket(t, f.pool)
	page := f.postLogin(t, nil)
	m := csrfValue.FindStringSubmatch(page.Body.String())
	if m == nil || !strings.Contains(page.Body.String(), `name="age"`) {
		t.Fatalf("the prompt was not shown: %s", truncate(page.Body.String(), 300))
	}
	form := url.Values{"prompt": {slug}, "version": {"1"}, "age": {"forty"}, csrfFormField: {m[1]}}
	r := httptest.NewRequest(http.MethodPost, "/login/prompt", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept-Language", "ar")
	r.AddCookie(cookieFrom(page, PendingCookieName))
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	if c := cookieFrom(rec, SessionCookieName); c != nil && c.Value != "" {
		t.Fatal("an answer the attribute refused signed somebody in")
	}
	if body := rec.Body.String(); !strings.Contains(body, "يجب أن تكون قيمة الحقل «Age in years» رقمًا.") ||
		strings.Contains(body, "is a number") {
		t.Errorf("the refusal is not in Arabic, naming the field: %s", truncate(body, 600))
	}
}
