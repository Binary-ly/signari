package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/risk"
)

// `risk_elevated` reaches the sign-in (4.10): a flow asking for the second
// factor only when risk is elevated asks after impossible travel or from a
// new country, and not from where the person always is, nor the first time.
// The language had the condition and the sign-in read it false.

func (f *signInFixture) signInFrom(t *testing.T, ip string) *httptest.ResponseRecorder {
	t.Helper()
	get := httptest.NewRecorder()
	f.srv.handleLoginGet(get, httptest.NewRequest(http.MethodGet, "/login", nil))
	m := csrfValue.FindStringSubmatch(get.Body.String())
	form := url.Values{"username": {f.email}, "password": {signInTestPassword}, csrfFormField: {m[1]}}
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookieFrom(get, CSRFCookieName))
	r.RemoteAddr = ip + ":5555"
	rec := httptest.NewRecorder()
	f.srv.rateLimitedLogin(rec, r)
	return rec
}

func TestRiskElevatedAsksForTheSecondFactor(t *testing.T) {
	f, _ := enrolFixture(t)
	giveTOTP(t, f)
	ctx := context.Background()
	// London, Paris and São Paulo.
	t.Setenv("SIGNARI_GEOIP_STATIC",
		"192.0.2.0/25=GB,51.51,-0.13;192.0.2.128/25=FR,48.86,2.35;198.51.100.0/24=BR,-23.55,-46.63")
	f.srv.geo = risk.NewResolver()
	f.applyFlow(t, `
version: 1
flows:
  - name: ask-when-risky
    on: authentication
    stages:
      - password
      - {stage: mfa, when: risk_elevated}
      - session
    tests:
      - {name: calm, given: {}, expect: [password, session]}
      - {name: risky, given: {risk_elevated: true}, expect: [password, mfa, session]}
`)
	asked := func(rec *httptest.ResponseRecorder) bool {
		return cookieFrom(rec, SessionCookieName) == nil && cookieFrom(rec, PendingCookieName) != nil
	}
	history := func(country string, lat, lon float64, ago string) {
		t.Helper()
		if _, err := f.pool.Exec(ctx, `DELETE FROM core.auth_locations WHERE user_id = $1::uuid`,
			f.userID); err != nil {
			t.Fatal(err)
		}
		if country == "" {
			return
		}
		if _, err := f.pool.Exec(ctx, `
			INSERT INTO core.auth_locations (user_id, org_id, country, latitude, longitude, source, occurred_at)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, 'geoip', now() - $6::interval)`,
			f.userID, f.orgID, country, lat, lon, ago); err != nil {
			t.Fatal(err)
		}
	}

	history("", 0, 0, "")
	if rec := f.signInFrom(t, "198.51.100.7"); asked(rec) {
		t.Error("a first sign-in, with no history, was treated as risky")
	}
	history("GB", 51.51, -0.13, "1 hour")
	if rec := f.signInFrom(t, "192.0.2.10"); asked(rec) {
		t.Error("a sign-in from where the person signed in an hour ago was treated as risky")
	}
	history("GB", 51.51, -0.13, "1 hour")
	if rec := f.signInFrom(t, "198.51.100.7"); !asked(rec) {
		t.Error("London to São Paulo in an hour was not treated as risky")
	}
	history("GB", 51.51, -0.13, "7 days")
	if rec := f.signInFrom(t, "192.0.2.200"); !asked(rec) {
		t.Error("a first sign-in from France, a week after London, was not treated as risky")
	}
}
