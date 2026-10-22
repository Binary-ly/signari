package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/store"
)

// Several accounts in one browser (5.17).

// twoAccounts is the fixture's person, A, and a second, B, in the same
// organisation, both with the fixture's password.
type twoAccounts struct {
	*signInFixture
	authz          string
	emailB, userB  string
	browser        *testBrowser
	sidA, sidB     string
	tokenA, tokenB string
}

func newTwoAccounts(t *testing.T) *twoAccounts {
	t.Helper()
	f := newSignInFixture(t)
	ctx := context.Background()
	ta := &twoAccounts{signInFixture: f}
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, 'b-' || substr(gen_random_uuid()::text, 1, 8) || '@example.test',
		        decode(md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text) ||
		               md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text), 'hex'))
		RETURNING id::text, email`, f.orgID).Scan(&ta.userB, &ta.emailB); err != nil {
		t.Fatal(err)
	}
	hash, err := passwords.NewHasher(passwords.MemoryBudgetMiB).Hash(ctx, signInTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm)
		VALUES ($1::uuid, $2::uuid, $3, 'argon2id')`, ta.userB, f.orgID, hash); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.pool.Exec(c, `DELETE FROM core.sessions WHERE user_id = $1::uuid`, ta.userB)
		_, _ = f.pool.Exec(c, `DELETE FROM core.users WHERE id = $1::uuid`, ta.userB)
	})
	ta.authz = url.Values{"client_id": {f.clientID}, "response_type": {"code"},
		"redirect_uri": {"https://rp.test/cb"}, "scope": {"openid"}, "state": {"s"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"}}.Encode()
	ta.browser = newTestBrowser(t, f.srv.Routes())
	clearSignInBucket(t, f.pool)
	return ta
}

// signIn signs in as email through the application's sign-in page, and
// returns the session the browser then uses.
func (ta *twoAccounts) signIn(t *testing.T, email string, extra url.Values) (sid, token string) {
	t.Helper()
	page := ta.browser.get("/login?authz=" + url.QueryEscape(ta.authz))
	form := url.Values{"username": {email}, "password": {signInTestPassword}, "authz": {ta.authz}}
	for k, v := range extra {
		form[k] = v
	}
	rec := ta.browser.post("/login", page, form)
	token = ta.browser.value(SessionCookieName)
	if rec.Code != http.StatusSeeOther || token == "" {
		t.Fatalf("signing in as %s: %d %s", email, rec.Code, truncate(rec.Body.String(), 300))
	}
	sid, _, err := store.ResolveSessionCookie(context.Background(), ta.pool, store.HashToken(token))
	if err != nil || sid == "" {
		t.Fatalf("the session for %s: %v", email, err)
	}
	return sid, token
}

// codeHolder is whose code the authorization redirect carries.
func (ta *twoAccounts) codeHolder(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), "https://rp.test/cb") || loc.Query().Get("code") == "" {
		t.Fatalf("no code for the application: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	var user string
	if err := ta.pool.QueryRow(context.Background(), `SELECT user_id::text FROM core.authorization_codes WHERE code_hash = $1`,
		store.HashToken(loc.Query().Get("code"))).Scan(&user); err != nil {
		t.Fatal(err)
	}
	return user
}

func (ta *twoAccounts) picker(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	return ta.browser.get(oidc.PathAuthorize + "?" + ta.authz + "&prompt=select_account")
}

// Two accounts, choose one: signing in as B keeps A signed in beside it, and
// prompt=select_account offers both and issues the code to the one chosen.
func TestTwoAccountsInOneBrowserAndChooseOne(t *testing.T) {
	ta := newTwoAccounts(t)
	ta.sidA, ta.tokenA = ta.signIn(t, ta.email, nil)
	ta.sidB, ta.tokenB = ta.signIn(t, ta.emailB, nil)
	if ta.browser.value(ParkedCookieName) != ta.tokenA {
		t.Fatalf("signing in as B did not keep A signed in: parked %q", ta.browser.value(ParkedCookieName))
	}

	page := ta.picker(t)
	body := page.Body.String()
	if page.Code != http.StatusOK || !strings.Contains(body, ta.email) || !strings.Contains(body, ta.emailB) {
		t.Fatalf("prompt=select_account did not offer both accounts: %d %s", page.Code, truncate(body, 400))
	}
	chosen := ta.browser.post("/login/accounts", page, url.Values{"account": {ta.sidA}, "authz": {ta.authz + "&prompt=select_account"}})
	if loc := chosen.Header().Get("Location"); strings.Contains(loc, "select_account") {
		t.Errorf("choosing resumed with select_account still asked for: %s", loc)
	}
	if got := ta.codeHolder(t, ta.browser.follow(chosen)); got != ta.userID {
		t.Errorf("the code went to %s, want A, %s", got, ta.userID)
	}
	if ta.browser.value(SessionCookieName) != ta.tokenA || ta.browser.value(ParkedCookieName) != ta.tokenB {
		t.Errorf("after choosing A: in use %v, parked %v", ta.browser.value(SessionCookieName) == ta.tokenA,
			ta.browser.value(ParkedCookieName) == ta.tokenB)
	}

	// Cancelled, the application is told no account was chosen.
	page = ta.picker(t)
	if loc := ta.browser.post("/login/accounts", page, url.Values{"cancel": {"1"},
		"authz": {ta.authz + "&prompt=select_account"}}).Header().Get("Location"); !strings.Contains(loc, "error=account_selection_required") {
		t.Errorf("a cancelled choice: %q", loc)
	}

	// The request comes back from the form, so a cancel is reported only to a
	// redirect the client registered, not to one written into the form.
	page = ta.picker(t)
	forged := strings.Replace(ta.authz, url.QueryEscape("https://rp.test/cb"), url.QueryEscape("https://elsewhere.test/cb"), 1)
	if loc := ta.browser.post("/login/accounts", page, url.Values{"cancel": {"1"},
		"authz": {forged}}).Header().Get("Location"); strings.Contains(loc, "elsewhere.test") {
		t.Errorf("a cancel was reported to an unregistered redirect: %q", loc)
	}

	// Only what this browser holds can be chosen.
	page = ta.picker(t)
	if body := ta.browser.post("/login/accounts", page, url.Values{"account": {"someone-elses-sid"},
		"authz": {ta.authz}}).Body.String(); !strings.Contains(body, "no longer signed in here") ||
		ta.browser.value(SessionCookieName) != ta.tokenA {
		t.Errorf("a sid this browser does not hold changed the account in use")
	}

	// A sign-out ends both.
	confirm := ta.browser.get(oidc.PathEndSession)
	ta.browser.post(oidc.PathEndSession, confirm, url.Values{})
	var live int
	if err := ta.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.sessions
		WHERE sid = ANY($1) AND revoked_at IS NULL`, []string{ta.sidA, ta.sidB}).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 || ta.browser.value(SessionCookieName) != "" || ta.browser.value(ParkedCookieName) != "" {
		t.Errorf("after signing out: %d live session(s), session cookie %q, parked %q", live,
			ta.browser.value(SessionCookieName), ta.browser.value(ParkedCookieName))
	}
}

// A parked session that ended elsewhere is not offered, nor is an
// impersonation session, and with nothing to choose the prompt asks for a
// sign-in.
func TestThePickerOffersOnlyLiveAccountsOfThisOrganisation(t *testing.T) {
	ta := newTwoAccounts(t)
	ta.sidA, ta.tokenA = ta.signIn(t, ta.email, nil)
	ta.sidB, ta.tokenB = ta.signIn(t, ta.emailB, nil)
	ctx := context.Background()
	if body := ta.picker(t).Body.String(); !strings.Contains(body, ta.email) || !strings.Contains(body, ta.emailB) {
		t.Fatalf("both accounts are not offered to begin with: %s", truncate(body, 300))
	}
	if _, err := ta.pool.Exec(ctx, `UPDATE core.sessions SET revoked_at = now(), revocation_reason = $2
		WHERE sid = $1`, ta.sidA, string(store.ReasonLogout)); err != nil {
		t.Fatal(err)
	}
	if body := ta.picker(t).Body.String(); strings.Contains(body, ta.email) || !strings.Contains(body, ta.emailB) {
		t.Errorf("an ended session was offered, or the live one was not: %s", truncate(body, 300))
	}
	if _, err := ta.pool.Exec(ctx, `UPDATE core.sessions SET impersonator_id = $2::uuid WHERE sid = $1`,
		ta.sidB, ta.userID); err != nil {
		t.Fatal(err)
	}
	if rec := ta.picker(t); !strings.Contains(rec.Body.String(), `action="/login"`) {
		t.Errorf("with nothing to choose, select_account did not ask for a sign-in: %d %s", rec.Code, truncate(rec.Body.String(), 300))
	}
}

// A sixth account signs out the one set aside longest ago, rather than leaving
// its session live with nothing in the browser to end it.
func TestASixthAccountSignsOutTheOldest(t *testing.T) {
	ta := newTwoAccounts(t)
	ctx := context.Background()
	var hash string
	if err := ta.pool.QueryRow(ctx, `SELECT hash FROM core.password_credentials WHERE user_id = $1::uuid`,
		ta.userID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	emails := []string{ta.email, ta.emailB}
	for i := 0; i < 4; i++ {
		var id, email string
		if err := ta.pool.QueryRow(ctx, `
			INSERT INTO core.users (org_id, email, user_handle)
			VALUES ($1::uuid, 'n-' || substr(gen_random_uuid()::text, 1, 8) || '@example.test',
			        decode(md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text) ||
			               md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text), 'hex'))
			RETURNING id::text, email`, ta.orgID).Scan(&id, &email); err != nil {
			t.Fatal(err)
		}
		if _, err := ta.pool.Exec(ctx, `INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm)
			VALUES ($1::uuid, $2::uuid, $3, 'argon2id')`, id, ta.orgID, hash); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			c := context.Background()
			_, _ = ta.pool.Exec(c, `DELETE FROM core.sessions WHERE user_id = $1::uuid`, id)
			_, _ = ta.pool.Exec(c, `DELETE FROM core.users WHERE id = $1::uuid`, id)
		})
		emails = append(emails, email)
	}
	var first string
	for i, e := range emails {
		sid, _ := ta.signIn(t, e, nil)
		if i == 0 {
			first = sid
		}
	}
	var revoked bool
	if err := ta.pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM core.sessions WHERE sid = $1`, first).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if parked := strings.Split(ta.browser.value(ParkedCookieName), "."); !revoked || len(parked) != maxParkedAccounts {
		t.Errorf("after six sign-ins: the first session revoked %v, %d parked; want true and %d", revoked, len(parked), maxParkedAccounts)
	}
}

// Each parked session keeps the lifetime it was signed in with: one that
// asked to stay signed in outlasts the browser wherever it is held, one that
// did not ends with it.
func TestAParkedSessionKeepsItsLifetime(t *testing.T) {
	ta := newTwoAccounts(t)
	ctx := context.Background()
	if _, err := ta.pool.Exec(ctx, `UPDATE core.organizations SET persistent_sessions = true WHERE id = $1::uuid`, ta.orgID); err != nil {
		t.Fatal(err)
	}
	ta.sidA, ta.tokenA = ta.signIn(t, ta.email, url.Values{stayField: {"1"}})
	ta.sidB, ta.tokenB = ta.signIn(t, ta.emailB, nil)
	kept := ta.browser.jar[KeptParkedCookieName]
	if kept == nil || kept.Value != ta.tokenA || kept.MaxAge <= 0 || ta.browser.value(ParkedCookieName) != "" {
		t.Fatalf("A, signed in to stay, is not parked in the lasting cookie: %+v, browser-session %q",
			kept, ta.browser.value(ParkedCookieName))
	}
	page := ta.picker(t)
	chosen := ta.browser.post("/login/accounts", page, url.Values{"account": {ta.sidA}, "authz": {ta.authz}})
	var session, parked *http.Cookie
	for _, c := range chosen.Result().Cookies() {
		switch c.Name {
		case SessionCookieName:
			session = c
		case ParkedCookieName:
			parked = c
		}
	}
	if session == nil || session.Value != ta.tokenA || session.MaxAge <= 0 {
		t.Errorf("A back in use without its lasting cookie: %+v", session)
	}
	if parked == nil || parked.Value != ta.tokenB || parked.MaxAge != 0 {
		t.Errorf("B, signed in to end with the browser, parked as %+v (all: %v)", parked, chosen.Header()["Set-Cookie"])
	}
}
