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

	"signari.dev/engine/internal/passwords"
)

// One address in two organisations, with a different password in each. Sign-in
// names are unique per organisation, so this is an ordinary state, and the
// password form looked the address up across all of them: it signed in to
// whichever account the planner returned, or refused the right person.

type twoTenantLogin struct {
	f                   *signInFixture
	otherOrg, otherUser string
	otherClient         string
	otherPassword       string
}

func newTwoTenantLogin(t *testing.T) *twoTenantLogin {
	t.Helper()
	f := newSignInFixture(t)
	ctx := context.Background()
	tl := &twoTenantLogin{f: f, otherPassword: "the-other-organisations-password-2026"}

	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, 'tt-' || substr(gen_random_uuid()::text, 1, 8), 'Other'
		  FROM core.organizations WHERE id = $1::uuid RETURNING id::text`, f.orgID).Scan(&tl.otherOrg); err != nil {
		t.Fatal(err)
	}
	hash, err := passwords.NewHasher(passwords.MemoryBudgetMiB).Hash(ctx, tl.otherPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, $2, decode(md5($2)||md5($1::text)||md5($2)||md5($1::text), 'hex'))
		RETURNING id::text`, tl.otherOrg, f.email).Scan(&tl.otherUser); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm)
		VALUES ($1::uuid, $2::uuid, $3, 'argon2id')`, tl.otherUser, tl.otherOrg, hash); err != nil {
		t.Fatal(err)
	}
	tl.otherClient = fmt.Sprintf("tt-%d", time.Now().UnixNano())
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, grant_types, scopes, require_pkce)
		VALUES ($1, $2::uuid, 'T', 'public', '', ARRAY['authorization_code'], ARRAY['openid'], true)`,
		tl.otherClient, tl.otherOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO core.client_redirect_uris (client_id, redirect_uri) VALUES ($1, 'https://rp.test/cb')`,
		tl.otherClient); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.pool.Exec(c, `DELETE FROM core.sessions WHERE user_id = $1::uuid`, tl.otherUser)
		_, _ = f.pool.Exec(c, `DELETE FROM core.clients WHERE client_id = $1`, tl.otherClient)
	})
	return tl
}

// signIn posts the password form from an application's authorization request
// (clientID non-empty) or from a bare sign-in page. It returns whose session
// row was created, if anybody's, and the page shown.
func (tl *twoTenantLogin) signIn(t *testing.T, clientID, password string) (string, string) {
	t.Helper()
	f := tl.f
	ctx := context.Background()
	authz := ""
	if clientID != "" {
		authz = url.Values{"client_id": {clientID}, "response_type": {"code"},
			"redirect_uri": {"https://rp.test/cb"}, "scope": {"openid"},
			// Public clients send a challenge (0137).
			"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
			"code_challenge_method": {"S256"}}.Encode()
	}
	before := time.Now()

	get := httptest.NewRecorder()
	f.srv.handleLoginGet(get, httptest.NewRequest(http.MethodGet, "/login", nil))
	m := csrfValue.FindStringSubmatch(get.Body.String())
	if m == nil {
		t.Fatal("no CSRF field")
	}
	var csrfCookie string
	for _, c := range get.Result().Cookies() {
		if c.Name == CSRFCookieName {
			csrfCookie = c.Value
		}
	}
	form := url.Values{"username": {f.email}, "password": {password}, "authz": {authz},
		csrfFormField: {m[1]}}
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfCookie})
	r.RemoteAddr = testClientIP(t) + ":5555"
	rec := httptest.NewRecorder()
	f.srv.rateLimitedLogin(rec, r)

	var who string
	_ = f.pool.QueryRow(ctx, `
		SELECT user_id::text FROM core.sessions
		 WHERE user_id IN ($1::uuid, $2::uuid) AND created_at >= $3
		 ORDER BY created_at DESC LIMIT 1`, f.userID, tl.otherUser, before).Scan(&who)
	return who, rec.Body.String()
}

func TestEachOrganisationsApplicationSignsInItsOwnAccount(t *testing.T) {
	tl := newTwoTenantLogin(t)
	clearOfWindowEdge(t, signInPerAccountWindow)

	if who, _ := tl.signIn(t, tl.f.clientID, signInTestPassword); who != tl.f.userID {
		t.Fatalf("signing in from the first organisation's application created a session for %q, "+
			"want the first organisation's account", who)
	}
	if who, _ := tl.signIn(t, tl.otherClient, tl.otherPassword); who != tl.otherUser {
		t.Fatalf("signing in from the second organisation's application created a session for %q, "+
			"want the second organisation's account", who)
	}
	// One organisation's password does not open the other's account.
	if who, _ := tl.signIn(t, tl.f.clientID, tl.otherPassword); who != "" {
		t.Fatalf("the second organisation's password opened %q from the first's application", who)
	}
}

// A session is a sign-in to its own organisation only. A person signed in to
// one organisation who opens another's application is sent to sign in, not
// issued a code: nothing compared the two, so anybody able to sign in
// anywhere could be issued any tenant's tokens.
func TestASessionFromAnotherOrganisationIsNoSignInForThisClient(t *testing.T) {
	f := newSignInFixture(t)
	cookie := f.signInAndReturnCookie(t)
	if cookie == "" {
		t.Fatal("the fixture user could not sign in")
	}
	ctx := context.Background()
	var otherOrg string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, 'xo-' || substr(gen_random_uuid()::text, 1, 8), 'Other'
		  FROM core.organizations WHERE id = $1::uuid RETURNING id::text`, f.orgID).Scan(&otherOrg); err != nil {
		t.Fatal(err)
	}
	otherClient := fmt.Sprintf("xo-%d", time.Now().UnixNano())
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, grant_types, scopes, require_pkce)
		VALUES ($1, $2::uuid, 'T', 'public', '', ARRAY['authorization_code'], ARRAY['openid'], true)`,
		otherClient, otherOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO core.client_redirect_uris (client_id, redirect_uri) VALUES ($1, 'https://rp.test/cb')`,
		otherClient); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, otherClient)
	})
	authorize := func(prompt string) *httptest.ResponseRecorder {
		q := url.Values{"client_id": {otherClient}, "response_type": {"code"},
			"redirect_uri": {"https://rp.test/cb"}, "scope": {"openid"}, "state": {"s"},
			"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
			"code_challenge_method": {"S256"}}
		if prompt != "" {
			q.Set("prompt", prompt)
		}
		r := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		return rec
	}

	rec := authorize("")
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "code=") {
		t.Fatalf("another organisation's session was issued a code: %s", loc)
	}
	if !strings.Contains(rec.Body.String(), "different organisation") {
		t.Errorf("the page does not say why sign-in is asked for again (%d)", rec.Code)
	}

	rec = authorize("none")
	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "code=") || !strings.Contains(loc, "error=login_required") {
		t.Fatalf("prompt=none from another organisation's session: %d %s", rec.Code, loc)
	}
}

// A bare sign-in page on a deployment with several organisations cannot say
// whose it is, and does not choose.
func TestABarePageDoesNotChooseBetweenTwoAccounts(t *testing.T) {
	tl := newTwoTenantLogin(t)
	clearOfWindowEdge(t, signInPerAccountWindow)
	who, page := tl.signIn(t, "", signInTestPassword)
	if who != "" {
		t.Fatalf("a bare sign-in page chose account %q for an address held in two organisations", who)
	}
	if !strings.Contains(page, "start from the") {
		t.Error("the refusal does not say to start from the application")
	}
}

// Recovery writes to every account the address holds, rather than to one of
// them at random.
func TestRecoveryReachesEveryAccountTheAddressHolds(t *testing.T) {
	tl := newTwoTenantLogin(t)
	ctx := context.Background()
	if err := tl.f.srv.beginRecovery(ctx, tl.f.email); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tl.f.pool.QueryRow(ctx, `
		SELECT count(DISTINCT user_id) FROM core.recovery_requests
		 WHERE user_id IN ($1::uuid, $2::uuid)`, tl.f.userID, tl.otherUser).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("recovery was started for %d of the address's two accounts", n)
	}
}
