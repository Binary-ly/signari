package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A noisy tenant spends its own budget, not another's (6.10).

func TestOneOrganisationsTokenBudgetLeavesAnothersWhole(t *testing.T) {
	a, b := newTokenFixture(t), newTokenFixture(t)
	ctx := context.Background()
	clearOfWindowEdge(t, time.Minute)
	secrets := map[*tokenFixture]string{}
	for _, f := range []*tokenFixture{a, b} {
		secret, hash := newTestSecret(t)
		secrets[f] = secret
		if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET grant_types = ARRAY['client_credentials'],
			client_type = 'confidential', client_secret_hash = $2, scopes = ARRAY['api']
			WHERE client_id = $1`, f.clientID, hash); err != nil {
			t.Fatal(err)
		}
		org := f.orgID
		t.Cleanup(func() {
			_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.rate_limits WHERE bucket_key LIKE $1`,
				"org:"+org+":%")
		})
	}
	// B's budget is small too, so A's three requests counted against anything
	// shared would leave B none.
	if _, err := a.pool.Exec(ctx, `UPDATE core.organizations SET token_budget_per_minute =
		CASE WHEN id = $1::uuid THEN 2 ELSE 3 END WHERE id IN ($1::uuid, $2::uuid)`, a.orgID, b.orgID); err != nil {
		t.Fatal(err)
	}

	// Both through one server: the budget is the organisation's, wherever its
	// requests land.
	ask := func(f *tokenFixture) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(url.Values{
			"grant_type": {"client_credentials"}, "client_id": {f.clientID},
			"client_secret": {secrets[f]}, "scope": {"api"},
		}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = freshAddress() + ":443"
		rec := httptest.NewRecorder()
		a.srv.Routes().ServeHTTP(rec, req)
		return rec
	}
	for i := 0; i < 2; i++ {
		if rec := ask(a); rec.Code != http.StatusOK {
			t.Fatalf("request %d within the budget answered %d: %s", i+1, rec.Code, rec.Body.String())
		}
	}
	rec := ask(a)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusTooManyRequests || out["error"] != "temporarily_unavailable" || rec.Header().Get("Retry-After") == "" {
		t.Errorf("past its budget the organisation's client answered %d %v, Retry-After %q",
			rec.Code, out, rec.Header().Get("Retry-After"))
	}
	if rec := ask(b); rec.Code != http.StatusOK {
		t.Errorf("another organisation's client was refused once the first spent its budget: %d %s",
			rec.Code, rec.Body.String())
	}
}

func TestOneOrganisationsSignInBudgetLeavesAnothersWhole(t *testing.T) {
	a, b := newSignInFixture(t), newSignInFixture(t)
	ctx := context.Background()
	clearOfWindowEdge(t, time.Minute)
	for _, f := range []*signInFixture{a, b} {
		org := f.orgID
		t.Cleanup(func() {
			_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.rate_limits WHERE bucket_key LIKE $1`,
				"org:"+org+":%")
		})
	}
	// B's budget is small too: A's two attempts counted against anything
	// shared would leave B none.
	if _, err := a.pool.Exec(ctx, `UPDATE core.organizations SET signin_budget_per_minute =
		CASE WHEN id = $1::uuid THEN 1 ELSE 2 END WHERE id IN ($1::uuid, $2::uuid)`, a.orgID, b.orgID); err != nil {
		t.Fatal(err)
	}

	attempt := func(f *signInFixture) int {
		t.Helper()
		get := httptest.NewRequest(http.MethodGet, "/login", nil)
		grec := httptest.NewRecorder()
		a.srv.handleLoginGet(grec, get)
		var csrfCookie string
		for _, c := range grec.Result().Cookies() {
			if c.Name == CSRFCookieName {
				csrfCookie = c.Value
			}
		}
		const marker = `name="` + csrfFormField + `" value="`
		body := grec.Body.String()
		i := strings.Index(body, marker)
		if i < 0 {
			t.Fatal("the sign-in form carries no CSRF field")
		}
		rest := body[i+len(marker):]
		form := url.Values{"username": {f.email}, "password": {signInTestPassword},
			csrfFormField: {rest[:strings.Index(rest, `"`)]}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfCookie})
		req.RemoteAddr = freshAddress() + ":5555"
		rec := httptest.NewRecorder()
		a.srv.rateLimitedLogin(rec, req)
		return rec.Code
	}

	if code := attempt(a); code == http.StatusTooManyRequests {
		t.Fatalf("the first sign-in within the budget was refused")
	}
	if code := attempt(a); code != http.StatusTooManyRequests {
		t.Errorf("past its budget the organisation's sign-in answered %d, want 429", code)
	}
	if code := attempt(b); code == http.StatusTooManyRequests {
		t.Errorf("another organisation's sign-in was refused once the first spent its budget")
	}
}
