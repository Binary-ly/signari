package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// Every route that changes how the account signs in needs a recent sign-in and
// refuses an impersonation session. A live session was once enough, so a
// stolen cookie could register its own passkey, link its own external account
// or regenerate the recovery codes, and an administrator impersonating
// somebody could do the same.
func TestCredentialChangesNeedARecentSignInAndAreRefusedWhileImpersonating(t *testing.T) {
	f, cookie := enrolFixture(t)
	giveTOTP(t, f)
	ctx := context.Background()

	slug := fmt.Sprintf("gate-%d", time.Now().UnixNano())
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, scopes)
		VALUES ($1::uuid, $2, 'Gate OIDC', 'oidc', 'c', '{openid}')`, f.orgID, slug); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.identity_providers WHERE slug = $1`, slug)
	})

	page := accountGET(f, cookie, "/account/mfa/totp")
	m := csrfValue.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatal("the TOTP page carries no CSRF field")
	}
	var csrfCookie string
	for _, c := range page.Result().Cookies() {
		if c.Name == CSRFCookieName {
			csrfCookie = c.Value
		}
	}

	type route struct {
		method, path, dest string
		form               url.Values
		json               bool
	}
	routes := []route{
		{http.MethodPost, "/account/mfa/totp/start", "/account/mfa/totp", url.Values{}, false},
		{http.MethodPost, "/account/mfa/totp", "/account/mfa/totp", url.Values{"code": {"000000"}}, false},
		{http.MethodPost, "/account/mfa/email", "/account/mfa/email",
			url.Values{"step": {"send"}, "email": {"moved@example.test"}}, false},
		{http.MethodPost, "/account/mfa/sms", "/account/mfa/sms",
			url.Values{"step": {"send"}, "number": {"+447700900123"}}, false},
		{http.MethodPost, "/account/recovery", "/account/recovery", url.Values{}, false},
		{http.MethodPost, "/account/unlink/" + slug, "/account", url.Values{}, false},
		{http.MethodGet, "/account/link/" + slug, "/account/link/" + slug, nil, false},
		{http.MethodPost, "/account/passkeys/begin", "/account", nil, true},
		{http.MethodPost, "/account/passkeys/finish", "/account", nil, true},
		{http.MethodPost, "/account/passkeys/delete", "/account", url.Values{"id": {"x"}}, true},
	}
	send := func(rt route) *httptest.ResponseRecorder {
		var r *http.Request
		switch {
		case rt.form != nil:
			form := url.Values{}
			for k, v := range rt.form {
				form[k] = v
			}
			form.Set(csrfFormField, m[1])
			r = httptest.NewRequest(rt.method, rt.path, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		case rt.json:
			r = httptest.NewRequest(rt.method, rt.path, strings.NewReader(`{}`))
			r.Header.Set("Content-Type", "application/json")
		default:
			r = httptest.NewRequest(rt.method, rt.path, nil)
		}
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfCookie})
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		return rec
	}
	session := func(age string, impersonated bool) {
		t.Helper()
		var actor any
		if impersonated {
			actor = f.userID
		}
		if _, err := f.pool.Exec(ctx, `
			UPDATE core.sessions SET auth_time = now() - $2::interval, impersonator_id = $3::uuid
			 WHERE cookie_hash = $1`, store.HashToken(cookie), age, actor); err != nil {
			t.Fatal(err)
		}
	}
	jsonError := func(rec *httptest.ResponseRecorder) map[string]string {
		var out map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}

	session("1 hour", false)
	for _, rt := range routes {
		rec := send(rt)
		if rt.json {
			body := jsonError(rec)
			if rec.Code != http.StatusUnauthorized || body["error"] != "reauthentication_required" ||
				body["location"] != parkLogin(rt.dest) {
				t.Errorf("%s %s from an hour-old sign-in: %d %v, want 401 reauthentication_required to %s",
					rt.method, rt.path, rec.Code, body, parkLogin(rt.dest))
			}
			continue
		}
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != parkLogin(rt.dest) {
			t.Errorf("%s %s from an hour-old sign-in: %d to %q, want 303 to %s",
				rt.method, rt.path, rec.Code, rec.Header().Get("Location"), parkLogin(rt.dest))
		}
	}
	var started int
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM core.totp_enrolments WHERE user_id = $1::uuid`, f.userID).Scan(&started); err != nil {
		t.Fatal(err)
	}
	if started != 0 {
		t.Error("a TOTP replacement was started from an hour-old sign-in")
	}

	session("0 seconds", true)
	for _, rt := range routes {
		rec := send(rt)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s in an impersonation session: %d, want 403", rt.method, rt.path, rec.Code)
			continue
		}
		if rt.json && jsonError(rec)["error"] != "impersonation_refused" {
			t.Errorf("%s %s in an impersonation session: %v", rt.method, rt.path, jsonError(rec))
		}
	}

	// A fresh sign-in of one's own passes the gate; what each handler does
	// next is its own business.
	session("0 seconds", false)
	for _, rt := range routes {
		rec := send(rt)
		refused := rec.Header().Get("Location") == parkLogin(rt.dest) ||
			strings.Contains(rec.Body.String(), "signed in as somebody else") ||
			jsonError(rec)["error"] == "reauthentication_required"
		if refused {
			t.Errorf("%s %s from a fresh sign-in was refused by the gate: %d %s",
				rt.method, rt.path, rec.Code, rec.Body.String())
		}
	}
}
