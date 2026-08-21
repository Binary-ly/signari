package httpapi

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/captcha"
)

// `/signup` had no challenge at all, and `internal/flow`'s shipped enrolment
// flow has declared one since it was written:
//
//	- name: default-sign-up
//	  on: enrolment
//	  stages:
//	    - {stage: captcha, when: captcha_required}
//
// The only `captcha.Verify` call in the engine was on the sign-in path. So an
// operator who configured a provider got a challenge on the endpoint that checks
// a password and none on the endpoint that writes user rows and sends mail --
// while the flow file in their own configuration said otherwise.
//
// There were also no tests for `/signup` of any kind, which is the other half of
// why it went unnoticed.

// enableSelfSignup gives the fixture's organisation a rule, without which
// `/signup` answers 404 and every assertion about the page is made against an
// error page. The first version of these tests did exactly that and two of them
// passed against a 404.
func enableSelfSignup(t *testing.T, f *tokenFixture) {
	t.Helper()
	// `signupRule` resolves the organisation through `defaultOrg`, which joins
	// organisations to the INSTANCE whose issuer equals this server's. The
	// fixture gives its instance a RANDOM issuer, so that join finds nothing and
	// /signup answers 404 no matter which organisation the rule is written for.
	// Two earlier versions of this helper wrote the rule for f.orgID and for the
	// oldest organisation in the database; both left the page 404ing.
	//
	// So the server is pointed at the fixture's own instance for the duration of
	// the test, rather than a shared row being rewritten to match the server.
	//
	// (There are two such functions and they are not interchangeable:
	// `defaultOrg` is issuer-scoped and correct for a multi-tenant deployment;
	// `defaultOrgID` in abca.go takes the oldest organisation overall.)
	ctx := context.Background()
	var issuer string
	if err := f.pool.QueryRow(ctx, `
		SELECT i.issuer FROM core.instances i
		JOIN core.organizations o ON o.instance_id = i.id
		WHERE o.id = $1::uuid`, f.orgID).Scan(&issuer); err != nil {
		t.Fatal(err)
	}
	before := f.srv.cfg.Issuer
	f.srv.cfg.Issuer = issuer
	t.Cleanup(func() { f.srv.cfg.Issuer = before })

	orgID := f.orgID
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO core.signup_rules (org_id, allowed_domains)
		 VALUES ($1::uuid, ARRAY['example.test'])
		 ON CONFLICT (org_id) DO UPDATE SET allowed_domains = EXCLUDED.allowed_domains`,
		orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.signup_rules WHERE org_id = $1::uuid`, orgID)
	})
}

func withCaptcha(t *testing.T, f *tokenFixture) {
	t.Helper()
	before := f.srv.captcha
	f.srv.captcha = captcha.New(captcha.Config{
		Mode: captcha.ModeAlways, Provider: captcha.Turnstile,
		SiteKey: "site-key-for-the-test", Secret: "secret",
	}, nil)
	t.Cleanup(func() { f.srv.captcha = before })
}

// csrfPair issues a CSRF token by rendering the sign-up form, and returns the
// cookie so a POST can carry both halves.
func signupCSRF(t *testing.T, f *tokenFixture) (token string, cookie *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/signup", nil))
	for _, c := range rec.Result().Cookies() {
		if c.Name == CSRFCookieName {
			return c.Value, c
		}
	}
	t.Fatal("GET /signup issued no CSRF cookie")
	return "", nil
}

func TestSignUpRefusesAnUnsolvedChallenge(t *testing.T) {
	f := newTokenFixture(t)
	withCaptcha(t, f)
	tok, cookie := signupCSRF(t, f)

	const addr = "newcomer@example.test"
	form := url.Values{
		csrfFormField: {tok},
		"email":       {addr},
		"password":    {"a-perfectly-fine-password-42"},
		// No challenge response: exactly what a script posting the form sends.
	}
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	// Its own source address. `/signup` rate-limits ten attempts per hour per
	// address, counted in the DATABASE, and httptest gives every request the same
	// 192.0.2.1 -- so after ten runs of this test the eleventh is answered 429 and
	// the assertion below passes or fails on the wrong thing. It did.
	req.RemoteAddr = uniqueTestAddr(t) + ":54321"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "That challenge was not completed") {
		t.Errorf("sign-up did not refuse an unsolved challenge; the endpoint that "+
			"creates accounts and sends mail accepted a submission that never "+
			"solved one. Answered %d: %s", rec.Code, truncate(rec.Body.String(), 300))
	}

	// And nothing was created. The message alone could be shown by a page that
	// had already written the row.
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM core.users WHERE email = $1`, addr).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d account(s) exist for %s despite the challenge being refused", n, addr)
	}
}

// The widget has to be on the page, and the policy has to permit it. A challenge
// the browser blocks is indistinguishable from one nobody solved -- the person
// simply cannot sign up, and the log says the challenge was not completed.
func TestTheSignUpPageRendersTheChallengeAndPermitsIt(t *testing.T) {
	f := newTokenFixture(t)
	enableSelfSignup(t, f)
	withCaptcha(t, f)

	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/signup", nil))
	body := rec.Body.String()

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /signup answered %d, so nothing below is about the sign-up "+
			"page: %s", rec.Code, truncate(body, 200))
	}
	if !strings.Contains(body, "site-key-for-the-test") {
		t.Errorf("the sign-up form does not render the challenge widget: %s",
			truncate(body, 300))
	}

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src") {
		t.Errorf("the policy has no script-src, so the widget's script cannot "+
			"load and the form can never be submitted: %q", csp)
	}
	if !strings.Contains(csp, "challenges.cloudflare.com") {
		t.Errorf("the policy does not permit the configured provider: %q", csp)
	}
	// The widening must be conditional, not permanent.
	if !strings.Contains(csp, "base-uri 'none'") {
		t.Errorf("the invariant directives were lost when the policy was widened: %q", csp)
	}
}

// With no challenge configured, the page must not widen its policy at all.
func TestWithoutAChallengeTheSignUpPolicyStaysClosed(t *testing.T) {
	f := newTokenFixture(t)
	enableSelfSignup(t, f)

	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/signup", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /signup answered %d; a 404 has no policy to check", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "script-src") {
		t.Errorf("script-src is permitted on a deployment with no challenge "+
			"configured; the permission should exist exactly where it is used: %q", csp)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// The case the first version of these tests missed, found by mutation.
//
// Replacing the `data["Captcha"]` guard with `true` did not fail anything,
// because with no provider configured `captchaOrigins` returns nothing and the
// policy is unchanged either way. The guard only does work in the case in
// between: a provider IS configured, and adaptive mode has decided this visitor
// does not need a challenge yet. The widget is absent from the page, so the
// permission for it must be absent from the policy.
//
// Without that distinction the default deployment posture -- adaptive, no
// pressure -- would carry a third-party script-src on every rendered page while
// showing no third-party script.
func TestAnAdaptiveChallengeNotYetDueDoesNotWidenThePolicy(t *testing.T) {
	f := newTokenFixture(t)
	enableSelfSignup(t, f)

	before := f.srv.captcha
	f.srv.captcha = captcha.New(captcha.Config{
		Mode: captcha.ModeAdaptive, Provider: captcha.Turnstile,
		SiteKey: "site-key-for-the-test", Secret: "secret",
		FailuresBeforeChallenge: 3,
	}, nil)
	t.Cleanup(func() { f.srv.captcha = before })

	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/signup", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /signup answered %d", rec.Code)
	}

	body := rec.Body.String()
	if strings.Contains(body, "site-key-for-the-test") {
		t.Fatalf("a challenge was rendered although adaptive mode has seen no " +
			"failures, so this case is not the one it is meant to test")
	}
	if csp := rec.Header().Get("Content-Security-Policy"); strings.Contains(csp, "challenges.cloudflare.com") {
		t.Errorf("the policy permits the challenge provider on a page carrying no "+
			"challenge: %q", csp)
	}
}

// uniqueTestAddr returns an address from the documentation range that no other
// run has used, so per-address limits counted in the database do not leak
// between runs of the suite.
func uniqueTestAddr(t *testing.T) string {
	t.Helper()
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	// 203.0.113.0/24 is TEST-NET-3; the last octet plus two more from the
	// 198.51.100.0/24 space gives enough spread for a test suite.
	return fmt.Sprintf("198.%d.%d.%d", b[0], b[1], b[2])
}
