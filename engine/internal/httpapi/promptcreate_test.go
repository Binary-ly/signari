package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"signari.dev/engine/internal/oauth"
)

// prompt=create (5.17) and the list of prompt values discovery advertises.

// regexpSignIn is the finished sign-up page's sign-in link for a request.
var regexpSignIn = regexp.MustCompile(`href="(/login\?authz=[^"]+)"`)

// authorizeWith sends an authorization request from the fixture's client, with
// prompt when it is not empty and the session cookie when one is given.
func (j *passkeyJourney) authorizeWith(t *testing.T, prompt, session string) *httptest.ResponseRecorder {
	t.Helper()
	q := url.Values{"client_id": {j.clientID}, "response_type": {"code"},
		"redirect_uri": {"https://rp.test/cb"}, "scope": {"openid"}, "state": {"s"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"}}
	if prompt != "" {
		q.Set("prompt", prompt)
	}
	r := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	if session != "" {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
	}
	rec := httptest.NewRecorder()
	j.h.ServeHTTP(rec, r)
	return rec
}

// openSignup gives the fixture's organisation a sign-up rule that asks for no
// proved address, so a new account can sign straight in.
func (j *passkeyJourney) openSignup(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if _, err := j.pool.Exec(ctx, `INSERT INTO core.signup_rules (org_id, require_verified_email)
		VALUES ($1::uuid, false) ON CONFLICT (org_id) DO UPDATE SET require_verified_email = false`, j.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = j.pool.Exec(context.Background(), `DELETE FROM core.signup_rules WHERE org_id = $1::uuid`, j.orgID)
	})
}

// Every value in prompt_values_supported does what it says, and a value that
// is not there is refused. A value advertised with no case here fails, so the
// list cannot grow a value nothing acts on.
func TestEveryAdvertisedPromptDoesWhatItSays(t *testing.T) {
	j := newPasskeyJourney(t)
	signInPage := func(rec *httptest.ResponseRecorder) bool {
		return rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), `action="/login"`)
	}
	cases := map[string]func(t *testing.T){
		oauth.PromptNone: func(t *testing.T) {
			if loc := j.authorizeWith(t, "none", "").Header().Get("Location"); !strings.Contains(loc, "error=login_required") {
				t.Errorf("prompt=none with nobody signed in: %q", loc)
			}
		},
		oauth.PromptLogin: func(t *testing.T) {
			if rec := j.authorizeWith(t, "login", ""); !signInPage(rec) {
				t.Errorf("prompt=login did not ask for a sign-in: %d", rec.Code)
			}
		},
		oauth.PromptConsent: func(t *testing.T) {
			// Consent follows a sign-in, which nobody has made yet.
			if rec := j.authorizeWith(t, "consent", ""); !signInPage(rec) {
				t.Errorf("prompt=consent did not start with a sign-in: %d", rec.Code)
			}
		},
		oauth.PromptSelectAccount: func(t *testing.T) {
			if rec := j.authorizeWith(t, "select_account", ""); !signInPage(rec) {
				t.Errorf("prompt=select_account with no account to choose did not ask for a sign-in: %d", rec.Code)
			}
		},
		oauth.PromptCreate: func(t *testing.T) {
			// A sign-in form with a notice, which the sign-in page answers 401, as
			// it does a step-up's or another organisation's.
			rec := j.authorizeWith(t, "create", "")
			if !strings.Contains(rec.Body.String(), `action="/login"`) ||
				!strings.Contains(rec.Body.String(), "accounts cannot be created here") {
				t.Errorf("prompt=create where sign-up is closed: %d %s", rec.Code, truncate(rec.Body.String(), 200))
			}
			j.openSignup(t)
			rec = j.authorizeWith(t, "create", "")
			if loc := rec.Header().Get("Location"); rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/signup?authz=") {
				t.Errorf("prompt=create where sign-up is open: %d %q", rec.Code, loc)
			}
		},
	}
	for _, p := range oauth.SupportedPrompts {
		check, ok := cases[p]
		if !ok {
			t.Errorf("prompt_values_supported lists %q and nothing here checks what it does", p)
			continue
		}
		t.Run(p, check)
	}
	for _, unsupported := range []string{"Login", "registration", "login Create"} {
		loc := j.authorizeWith(t, unsupported, "").Header().Get("Location")
		if !strings.Contains(loc, "error=invalid_request") {
			t.Errorf("prompt=%q, which is not advertised, was not refused: %q", unsupported, loc)
		}
	}
}

// The whole of prompt=create: the application asks, the person makes the
// account, signs in with it, and the application gets its code.
func TestPromptCreateLeadsThroughSignUpToTheApplication(t *testing.T) {
	j := newPasskeyJourney(t)
	j.openSignup(t)
	clearSignInBucket(t, j.pool)
	serve := func(r *http.Request) *httptest.ResponseRecorder {
		r.RemoteAddr = uniqueTestAddr(t) + ":5555"
		rec := httptest.NewRecorder()
		j.h.ServeHTTP(rec, r)
		return rec
	}
	post := func(path string, page *httptest.ResponseRecorder, form url.Values) *httptest.ResponseRecorder {
		m := csrfValue.FindStringSubmatch(page.Body.String())
		if m == nil {
			t.Fatalf("no CSRF token on the page before %s: %s", path, truncate(page.Body.String(), 300))
		}
		form.Set(csrfFormField, m[1])
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
		return serve(r)
	}

	start := j.authorizeWith(t, "create", "")
	signupURL := start.Header().Get("Location")
	if !strings.HasPrefix(signupURL, "/signup?authz=") {
		t.Fatalf("prompt=create went to %q", signupURL)
	}
	form := serve(httptest.NewRequest(http.MethodGet, signupURL, nil))
	if !strings.Contains(form.Body.String(), `name="authz"`) {
		t.Fatalf("the sign-up form does not carry the request: %s", truncate(form.Body.String(), 300))
	}
	authz, _ := url.Parse(signupURL)
	carried := authz.Query().Get("authz")
	if strings.Contains(carried, "prompt=create") {
		t.Errorf("the carried request still says create, so signing in would come back here: %s", carried)
	}

	raw := make([]byte, 12)
	_, _ = rand.Read(raw)
	email := "made-" + hex.EncodeToString(raw[:4]) + "@example.test"
	password := "a-new-pass-" + hex.EncodeToString(raw)
	t.Cleanup(func() {
		_, _ = j.pool.Exec(context.Background(), `DELETE FROM core.users WHERE org_id = $1::uuid AND email = $2`, j.orgID, email)
	})
	done := post("/signup", form, url.Values{"email": {email}, "password": {password}, "authz": {carried}})
	m := regexpSignIn.FindStringSubmatch(done.Body.String())
	if m == nil {
		t.Fatalf("the finished sign-up does not lead to a sign-in for the request: %d %s", done.Code, truncate(done.Body.String(), 400))
	}
	next, err := url.Parse(html.UnescapeString(m[1]))
	if err != nil || next.Query().Get("authz") != carried {
		t.Fatalf("the sign-in link carries %q, want %q", next.Query().Get("authz"), carried)
	}

	login := serve(httptest.NewRequest(http.MethodGet, next.String(), nil))
	signedIn := post("/login", login, url.Values{"username": {email}, "password": {password}, "authz": {carried}})
	session := cookieFrom(signedIn, SessionCookieName)
	if session == nil {
		t.Fatalf("the new account did not sign in: %d %s", signedIn.Code, truncate(signedIn.Body.String(), 300))
	}
	resume := signedIn.Header().Get("Location")
	r := httptest.NewRequest(http.MethodGet, resume, nil)
	r.AddCookie(session)
	final := serve(r)
	if loc := final.Header().Get("Location"); !strings.HasPrefix(loc, "https://rp.test/cb?") || !strings.Contains(loc, "code=") {
		t.Errorf("the application did not get a code: %d %q (resumed at %q)", final.Code, loc, resume)
	}
}
