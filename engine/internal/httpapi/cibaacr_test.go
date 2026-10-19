package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// A CIBA request's acr_values hold the approval to them: a request asking for
// multi-factor is not approved from a password-only session, and stays pending
// so the person can sign in again with a second factor. The values were stored
// for exactly this and read by nothing (found by guard 0.08b).
func TestABackchannelRequestIsHeldToItsACR(t *testing.T) {
	f := newCIBAFixture(t)
	ctx := context.Background()
	form := f.goodRequest()
	form.Set("acr_values", oauth.ACRMultiFactor)
	code, body := f.backchannel(t, f.clientID, f.secret, form)
	if code != http.StatusOK {
		t.Fatalf("the backchannel request failed: %d %v", code, body)
	}
	authReqID, _ := body["auth_req_id"].(string)
	var id string
	if err := f.pool.QueryRow(ctx,
		`SELECT id::text FROM core.device_authorizations WHERE device_code_hash = $1`,
		store.HashToken(authReqID)).Scan(&id); err != nil {
		t.Fatal(err)
	}

	sessionWith := func(amr string) string {
		t.Helper()
		cookie := fmt.Sprintf("ciba-acr-%d", time.Now().UnixNano())
		if _, err := f.pool.Exec(ctx, `
			INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
			VALUES ($1, $2, $3::uuid, $4::uuid, '1', $5::text[], now(), now() + interval '1 hour')`,
			"sid-"+cookie, store.HashToken(cookie), f.orgID, f.userID, amr); err != nil {
			t.Fatal(err)
		}
		return cookie
	}
	approve := func(cookie string) (int, string) {
		t.Helper()
		get := httptest.NewRequest(http.MethodGet, "/account/requests", nil)
		get.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		page := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(page, get)
		m := csrfValue.FindStringSubmatch(page.Body.String())
		if m == nil {
			t.Fatalf("the requests page carries no CSRF field (status %d)", page.Code)
		}
		var csrfCookie string
		for _, c := range page.Result().Cookies() {
			if c.Name == CSRFCookieName {
				csrfCookie = c.Value
			}
		}
		post := httptest.NewRequest(http.MethodPost, "/account/requests", strings.NewReader(
			url.Values{"id": {id}, "decision": {"approve"}, csrfFormField: {m[1]}}.Encode()))
		post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		post.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		post.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfCookie})
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, post)
		return rec.Code, rec.Body.String()
	}
	status := func() string {
		t.Helper()
		var s string
		if err := f.pool.QueryRow(ctx, `SELECT status FROM core.device_authorizations WHERE id = $1::uuid`,
			id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	code, page := approve(sessionWith("{pwd}"))
	if s := status(); s != "pending" {
		t.Fatalf("a password-only session approved a request asking for multi-factor (now %s)", s)
	}
	if code != http.StatusOK || !strings.Contains(page, "second factor") {
		t.Errorf("the refusal did not say what to do: %d %.300s", code, page)
	}

	if code, _ := approve(sessionWith("{pwd,otp}")); code != http.StatusSeeOther {
		t.Fatalf("a multi-factor session's approval answered %d", code)
	}
	if s := status(); s != "approved" {
		t.Fatalf("a multi-factor session did not approve the request (now %s)", s)
	}
}
