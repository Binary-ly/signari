package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"signari.dev/engine/internal/oauth"
)

// A security key as the second factor, through the pages a browser walks: a
// password, the code page, the key's ceremony begun from that page, and its
// answer posted on that page's form. A passkey was only ever a way to sign in on
// its own, so a person whose one factor beyond the password was a key signed in
// on the password alone.

// mfaKeyStep is a browser that has just passed the password step.
type mfaKeyStep struct {
	j          *passkeyJourney
	page       *httptest.ResponseRecorder
	pending    *http.Cookie
	csrfCookie string
	csrfField  string
}

// passwordStep signs in with the fixture's password through the routes, from a
// browser holding nothing, carrying authz as the parked request.
func (j *passkeyJourney) passwordStep(t *testing.T, authz string) *mfaKeyStep {
	t.Helper()
	get := httptest.NewRecorder()
	j.h.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/login", nil))
	csrf := cookieFrom(get, CSRFCookieName)
	m := csrfValue.FindStringSubmatch(get.Body.String())
	if csrf == nil || m == nil {
		t.Fatal("the sign-in form carries no CSRF token")
	}
	form := url.Values{"username": {j.email}, "password": {signInTestPassword},
		csrfFormField: {m[1]}}
	if authz != "" {
		form.Set("authz", authz)
	}
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(csrf)
	r.RemoteAddr = testClientIP(t) + ":5555"
	rec := httptest.NewRecorder()
	j.h.ServeHTTP(rec, r)

	step := &mfaKeyStep{j: j, page: rec, pending: cookieFrom(rec, PendingCookieName),
		csrfCookie: csrf.Value}
	if pm := csrfValue.FindStringSubmatch(rec.Body.String()); pm != nil {
		step.csrfField = pm[1]
	}
	return step
}

// begin asks for the key's challenge, as the page's script does.
func (m *mfaKeyStep) begin(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	return m.j.post(t, "/login/mfa/webauthn/begin", nil, m.pending)
}

// submit posts the key's answer on the code page's form.
func (m *mfaKeyStep) submit(t *testing.T, assertion []byte, ceremony *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"assertion": {string(assertion)}, csrfFormField: {m.csrfField}}
	r := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(m.pending)
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m.csrfCookie})
	if ceremony != nil {
		r.AddCookie(ceremony)
	}
	r.RemoteAddr = testClientIP(t) + ":5555"
	rec := httptest.NewRecorder()
	m.j.h.ServeHTTP(rec, r)
	return rec
}

// withKey answers a begun ceremony with cred, bent as asked.
func (m *mfaKeyStep) withKey(t *testing.T, cred *virtualCredential, bend ...func(*ceremonyParts)) *httptest.ResponseRecorder {
	t.Helper()
	begin := m.begin(t)
	if begin.Code != http.StatusOK {
		t.Fatalf("the key's ceremony could not begin: %d %s", begin.Code, begin.Body)
	}
	return m.submit(t, m.j.auth.get(t, begin.Body.Bytes(), cred, bend...),
		cookieFrom(begin, CeremonyCookieName))
}

func TestAPasswordAndASecurityKeyAreTwoFactors(t *testing.T) {
	j := newPasskeyJourney(t)
	clearSignInBucket(t, j.pool)
	session := &http.Cookie{Name: SessionCookieName, Value: j.signInAndReturnCookie(t)}
	if session.Value == "" {
		t.Fatal("before a key is registered, the password alone signs in")
	}
	cred := j.register(t, session)

	// The password now leaves a pending sign-in, not a session, and the code
	// page offers the key, with a policy that lets its script run.
	step := j.passwordStep(t, "")
	if cookieFrom(step.page, SessionCookieName) != nil || step.pending == nil {
		t.Fatalf("a password produced a session for an account with a security key: %d", step.page.Code)
	}
	body := step.page.Body.String()
	if !strings.Contains(body, `id="mfa-key"`) || !strings.Contains(body, `src="/passkey.js"`) {
		t.Error("the code page does not offer the security key")
	}
	if csp := step.page.Result().Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("the code page's policy blocks the key's script: %q", csp)
	}

	rec := step.withKey(t, cred)
	amr, acr, ok := j.sessionFor(t, rec)
	if !ok {
		t.Fatalf("password and key produced no session: %d %s", rec.Code, rec.Body)
	}
	for _, want := range []string{"pwd", "user", "hwk", "mfa"} {
		if !slices.Contains(amr, want) {
			t.Errorf("the session's amr %q lacks %s", amr, want)
		}
	}
	if acr != oauth.ACRMultiFactor {
		t.Errorf("password and key gave acr %q, want %q", acr, oauth.ACRMultiFactor)
	}

	// A key that does not verify its user is asked for "preferred", and is
	// still the second of two factors with the password.
	rec = j.passwordStep(t, "").withKey(t, cred, func(p *ceremonyParts) { p.Flags = flagUP })
	if _, acr, ok := j.sessionFor(t, rec); !ok || acr != oauth.ACRMultiFactor {
		t.Errorf("a key without user verification after a password: session %v, acr %q (%d)",
			ok, acr, rec.Code)
	}

	// A parked authorization request resumes, which a fetch could not have
	// followed: the answer is a redirect, sent to a form submission.
	authz := url.Values{"client_id": {j.clientID}, "response_type": {"code"},
		"redirect_uri": {"https://rp.test/cb"}, "scope": {"openid"}, "state": {"s"}}.Encode()
	rec = j.passwordStep(t, authz).withKey(t, cred)
	if rec.Code != http.StatusSeeOther ||
		!strings.HasPrefix(rec.Header().Get("Location"), "/oauth2/authorize?client_id="+j.clientID) {
		t.Errorf("with a parked request the key answered %d to %q, want 303 to the authorization endpoint",
			rec.Code, rec.Header().Get("Location"))
	}
	if _, _, ok := j.sessionFor(t, rec); !ok {
		t.Error("with a parked request the key produced no session")
	}
}

func TestASecurityKeyThatProvesTheWrongThingIsRefused(t *testing.T) {
	j := newPasskeyJourney(t)
	clearSignInBucket(t, j.pool)
	ctx := context.Background()
	session := &http.Cookie{Name: SessionCookieName, Value: j.signInAndReturnCookie(t)}
	cred := j.register(t, session)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stranger := &virtualCredential{id: []byte("not-a-credential-of-this-account"),
		key: other, rpID: cred.rpID, handle: cred.handle}

	failures := func() int {
		var n int
		if err := j.pool.QueryRow(ctx, `SELECT COALESCE(sum(count),0) FROM core.rate_limits
			WHERE bucket_key = $1`, secondFactorAccountKey(j.userID)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	_, _ = j.pool.Exec(ctx, `DELETE FROM core.rate_limits WHERE bucket_key = $1`,
		secondFactorAccountKey(j.userID))

	cases := []struct {
		name string
		run  func(*mfaKeyStep) *httptest.ResponseRecorder
		// elsewhere is a refusal charged to the budget of the person the
		// pending cookie names, who is not the fixture user.
		elsewhere bool
	}{
		{"another key's signature", func(m *mfaKeyStep) *httptest.ResponseRecorder {
			return m.withKey(t, cred, func(p *ceremonyParts) { p.Key = other })
		}, false},
		{"a credential the account does not hold", func(m *mfaKeyStep) *httptest.ResponseRecorder {
			return m.withKey(t, stranger)
		}, false},
		{"another origin", func(m *mfaKeyStep) *httptest.ResponseRecorder {
			return m.withKey(t, cred, func(p *ceremonyParts) { p.Origin = "https://evil.test" })
		}, false},
		{"no user presence", func(m *mfaKeyStep) *httptest.ResponseRecorder {
			return m.withKey(t, cred, func(p *ceremonyParts) { p.Flags = flagUV })
		}, false},
		{"no ceremony", func(m *mfaKeyStep) *httptest.ResponseRecorder {
			begin := m.begin(t)
			return m.submit(t, m.j.auth.get(t, begin.Body.Bytes(), cred), nil)
		}, false},
		{"a sign-in ceremony, not this step's", func(m *mfaKeyStep) *httptest.ResponseRecorder {
			begin := m.j.post(t, "/login/passkey/begin", nil)
			return m.submit(t, m.j.auth.get(t, begin.Body.Bytes(), cred),
				cookieFrom(begin, CeremonyCookieName))
		}, false},
		{"a ceremony begun for somebody else's sign-in", func(m *mfaKeyStep) *httptest.ResponseRecorder {
			begin := m.begin(t)
			assertion := m.j.auth.get(t, begin.Body.Bytes(), cred)
			// The same browser, now pending as another person of the org.
			var otherUser string
			if err := m.j.pool.QueryRow(ctx, `
				INSERT INTO core.users (org_id, email, user_handle)
				VALUES ($1::uuid, 'k'||substr(gen_random_uuid()::text,1,8)||'@example.test',
				        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
				               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'))
				RETURNING id::text`, m.j.orgID).Scan(&otherUser); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = m.j.pool.Exec(context.Background(),
					`DELETE FROM core.users WHERE id = $1::uuid`, otherUser)
			})
			w := httptest.NewRecorder()
			if err := m.j.srv.setPendingCookie(w, otherUser, m.j.orgID, []string{"pwd"}, ""); err != nil {
				t.Fatal(err)
			}
			m.pending = cookieFrom(w, PendingCookieName)
			return m.submit(t, assertion, cookieFrom(begin, CeremonyCookieName))
		}, true},
	}
	charged := 0
	for _, c := range cases {
		rec := c.run(j.passwordStep(t, ""))
		if cookieFrom(rec, SessionCookieName) != nil {
			t.Errorf("%s: produced a session", c.name)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: answered %d, want 401 and the code page", c.name, rec.Code)
		}
		if !c.elsewhere {
			charged++
		}
		if got := failures(); got != charged {
			t.Errorf("%s: the step's budget holds %d failures, want %d", c.name, got, charged)
			charged = got
		}
	}
	_, _ = j.pool.Exec(ctx, `DELETE FROM core.rate_limits WHERE bucket_key = $1`,
		secondFactorAccountKey(j.userID))

	// One answer, posted twice: the ceremony is spent by the first.
	step := j.passwordStep(t, "")
	begin := step.begin(t)
	assertion := j.auth.get(t, begin.Body.Bytes(), cred)
	ceremony := cookieFrom(begin, CeremonyCookieName)
	if _, _, ok := j.sessionFor(t, step.submit(t, assertion, ceremony)); !ok {
		t.Fatal("the first answer produced no session")
	}
	if rec := step.submit(t, assertion, ceremony); cookieFrom(rec, SessionCookieName) != nil {
		t.Error("the same answer, posted again, produced a second session")
	}

	// The ceremony cannot be begun without a password step behind it.
	if rec := j.post(t, "/login/mfa/webauthn/begin", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("a ceremony was begun with no pending sign-in: %d", rec.Code)
	}
}

// Somebody with no key is not offered one, and their code page runs no script.
func TestTheCodePageOffersNoKeyToSomebodyWithout(t *testing.T) {
	f := newSignInFixture(t)
	m := newMFAStep(t, f)
	rec := m.submit("000000")
	if strings.Contains(rec.Body.String(), `id="mfa-key"`) {
		t.Error("the code page offers a key to somebody with none")
	}
	if csp := rec.Result().Header.Get("Content-Security-Policy"); strings.Contains(csp, "script-src") {
		t.Errorf("the code page allows script for somebody with no key: %q", csp)
	}
}
