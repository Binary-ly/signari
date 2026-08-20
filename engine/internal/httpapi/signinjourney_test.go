package httpapi

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/passwords"
)

// The browser sign-in journey, end to end.
//
// # Why this file exists
//
// Every piece of this path was already tested in isolation: the hasher in
// internal/passwords, the second-factor lookup in internal/store, the throttle,
// the CSRF token, the prompt machinery. What was NOT tested, anywhere, is the
// journey -- POST a password, and see what comes back.
//
// That gap matters more here than anywhere else in the product, because the
// property this path exists to hold is a NEGATIVE one: a correct password must
// not produce a session when a second factor is enrolled, when a prompt is
// outstanding, or when the credential is flagged. A negative property is exactly
// what unit tests of the parts cannot establish -- each part can be perfect
// while the handler forgets to call it, and the result at the HTTP boundary is
// indistinguishable from the part not existing.
//
// The tests assert on the two things a browser actually receives: whether a
// session cookie was set, and whether a session row exists. Not on which
// template rendered -- that changes for cosmetic reasons, and a test that fails
// when a heading is reworded gets deleted rather than read.

type signInFixture struct {
	srv    *Server
	pool   *pgxpool.Pool
	orgID  string
	userID string
	email  string
	// clientID is a relying party in the same organisation, for the tests that
	// need an authorization request rather than a bare sign-in.
	clientID string
}

const signInTestPassword = "correct-horse-battery-staple-2026"

func newSignInFixture(t *testing.T) *signInFixture {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set; skipping database-backed tests")
	}
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_maintenance")
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	set, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(oidc.Config{
		Issuer: "https://signin-test.example", Keys: set, AllowInsecureIssuer: true,
	}, pool, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	f := &signInFixture{srv: srv, pool: pool}
	if err := pool.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://si-' || gen_random_uuid() || '.test', 'T') RETURNING id
		), o AS (
			INSERT INTO core.organizations (instance_id, slug, display_name)
			SELECT id, 's' || substr(gen_random_uuid()::text,1,8), 'Org' FROM i RETURNING id
		)
		INSERT INTO core.users (org_id, email, user_handle)
		SELECT id, 's'||substr(gen_random_uuid()::text,1,8)||'@example.test',
		       decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		              md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex')
		FROM o RETURNING org_id::text, id::text, email`).
		Scan(&f.orgID, &f.userID, &f.email); err != nil {
		t.Fatalf("fixture user: %v", err)
	}

	// A real Argon2id hash, produced by the same hasher the handler verifies
	// with. A hand-written constant here would test the constant.
	hash, err := passwords.NewHasher(passwords.MemoryBudgetMiB).Hash(ctx, signInTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm)
		VALUES ($1::uuid, $2::uuid, $3, 'argon2id')`, f.userID, f.orgID, hash); err != nil {
		t.Fatalf("fixture credential: %v", err)
	}

	f.clientID = "si-" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, grant_types, scopes, require_pkce)
		VALUES ($1,$2,'T','public','', ARRAY['authorization_code'],
		        ARRAY['openid'], false)`, f.clientID, f.orgID); err != nil {
		t.Fatalf("fixture client: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO core.client_redirect_uris (client_id, redirect_uri) VALUES ($1,$2)`,
		f.clientID, "https://rp.test/cb"); err != nil {
		t.Fatalf("fixture redirect: %v", err)
	}

	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = pool.Exec(c, `DELETE FROM core.sessions WHERE user_id = $1::uuid`, f.userID)
		_, _ = pool.Exec(c, `DELETE FROM core.clients WHERE client_id = $1`, f.clientID)
	})

	// A previous run of THIS test must not be able to fail this one.
	clearSignInBucket(t, f.pool)
	return f
}

// outcome is what the browser got back from one sign-in attempt.
type outcome struct {
	status        int
	sessionCookie string
	pendingCookie string
	body          string
}

// signedIn is the question every test in this file is really asking.
func (o outcome) signedIn() bool { return o.sessionCookie != "" }

// testClientIP gives each test its own source address.
//
// Every sign-in test used to post from 203.0.113.7, so they shared one
// `signin:fail:ip:` bucket in core.rate_limits. That bucket is keyed by a
// five-minute window and survives the process, so running the suite twice inside
// one window accumulated failures across BOTH runs and the twentieth tripped the
// limiter -- and the tests that then failed were whichever happened to run last,
// with a 429 that looks nothing like the assertion they were making.
//
// A suite whose result depends on how recently it was last run is not a suite.
// Deriving the address from the test name gives each one its own bucket;
// clearSignInBucket then makes a repeat run of the SAME test clean, which
// covers the collision case too.
func testClientIP(t *testing.T) string {
	t.Helper()
	h := fnv.New32a()
	_, _ = h.Write([]byte(t.Name()))
	return fmt.Sprintf("203.0.113.%d", h.Sum32()%254+1)
}

// clearSignInBucket drops the rate-limit rows for this test's address, so a
// previous run of it cannot make this one fail.
func clearSignInBucket(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM core.rate_limits WHERE bucket_key LIKE 'signin:%' || $1`,
		testClientIP(t)); err != nil {
		t.Fatalf("clearing the sign-in rate bucket: %v", err)
	}
}

// attempt runs one POST /login through the real entry point.
//
// Through rateLimitedLogin, not handleLoginPost, so the CSRF gate and the
// limiter are part of what is exercised. A test that called the inner handler
// would pass just as happily if the outer one stopped calling it.
func (f *signInFixture) attempt(t *testing.T, identifier, password string) outcome {
	t.Helper()

	// A real form first, for a CSRF token pair the POST will accept.
	get := httptest.NewRequest(http.MethodGet, "/login", nil)
	grec := httptest.NewRecorder()
	f.srv.handleLoginGet(grec, get)

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
	csrfField := rest[:strings.Index(rest, `"`)]

	form := url.Values{
		"username":     {identifier},
		"password":     {password},
		csrfFormField: {csrfField},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfCookie})
	req.RemoteAddr = testClientIP(t) + ":5555"

	rec := httptest.NewRecorder()
	f.srv.rateLimitedLogin(rec, req)

	out := outcome{status: rec.Code, body: rec.Body.String()}
	for _, c := range rec.Result().Cookies() {
		// A cookie being CLEARED is not a cookie being set. Without the MaxAge
		// check, clearPending's deletion would read as a pending state.
		if c.Value == "" || c.MaxAge < 0 {
			continue
		}
		switch c.Name {
		case SessionCookieName:
			out.sessionCookie = c.Value
		case PendingCookieName:
			out.pendingCookie = c.Value
		}
	}
	return out
}

func (f *signInFixture) sessionRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM core.sessions WHERE user_id = $1::uuid`, f.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestACorrectPasswordSignsSomebodyIn is the positive case, and it exists mostly
// so the negative cases below cannot pass by the whole path being broken.
func TestACorrectPasswordSignsSomebodyIn(t *testing.T) {
	f := newSignInFixture(t)

	got := f.attempt(t, f.email, signInTestPassword)
	if !got.signedIn() {
		t.Fatalf("a correct password did not produce a session cookie (status %d): %s",
			got.status, got.body)
	}
	if n := f.sessionRows(t); n != 1 {
		t.Fatalf("expected exactly one session row, found %d", n)
	}
	if got.pendingCookie != "" {
		t.Error("a completed sign-in also left a half-authenticated pending cookie")
	}
}

// TestAWrongPasswordDoesNotSignAnybodyIn.
func TestAWrongPasswordDoesNotSignAnybodyIn(t *testing.T) {
	f := newSignInFixture(t)

	got := f.attempt(t, f.email, "not the password")
	if got.signedIn() {
		t.Fatal("a wrong password produced a session cookie")
	}
	if n := f.sessionRows(t); n != 0 {
		t.Fatalf("a wrong password created %d session row(s)", n)
	}
	if got.pendingCookie != "" {
		t.Error("a wrong password produced a pending authentication")
	}
}

// TestAnUnknownIdentifierDoesNotSignAnybodyIn, and must be indistinguishable
// from a wrong password: distinguishing them is a user-enumeration oracle.
func TestAnUnknownIdentifierDoesNotSignAnybodyIn(t *testing.T) {
	f := newSignInFixture(t)

	unknown := f.attempt(t, "nobody-at-all@example.test", signInTestPassword)
	if unknown.signedIn() {
		t.Fatal("an unknown identifier produced a session")
	}

	wrong := f.attempt(t, f.email, "not the password")
	if unknown.status != wrong.status {
		t.Errorf("unknown user answers %d and wrong password answers %d; the difference "+
			"tells an attacker which usernames exist", unknown.status, wrong.status)
	}
	// Compared with the CSRF token normalised away. It is freshly minted on
	// every render, so a raw comparison differs on every run and would fail
	// whatever the handler did -- a test that cannot pass proves as little as one
	// that cannot fail.
	if normaliseCSRF(unknown.body) != normaliseCSRF(wrong.body) {
		t.Error("unknown user and wrong password render different pages; the difference " +
			"tells an attacker which usernames exist")
	}
}

// TestASecondFactorStopsThePasswordAlone is the property the whole MFA feature
// exists for, asserted at the boundary an attacker actually reaches.
//
// The parts were already covered: HasSecondFactor has its own tests, and
// internal/store/mfa_coverage_test.go even checks that it consults every
// credential table. None of that establishes that handleLoginPost calls it.
func TestASecondFactorStopsThePasswordAlone(t *testing.T) {
	f := newSignInFixture(t)

	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.totp_credentials (user_id, org_id, secret_enc, confirmed_at)
		VALUES ($1::uuid, $2::uuid, decode(md5('s'),'hex'), now())`,
		f.userID, f.orgID); err != nil {
		t.Fatalf("enrolling a second factor: %v", err)
	}

	got := f.attempt(t, f.email, signInTestPassword)
	if got.signedIn() {
		t.Fatal("a correct password produced a session for an account with a confirmed " +
			"second factor; the stolen password alone is already usable")
	}
	if n := f.sessionRows(t); n != 0 {
		t.Fatalf("a password-only attempt created %d session row(s) on an MFA account", n)
	}
	// What it should produce instead: a pending authentication that can do
	// nothing but present a code.
	if got.pendingCookie == "" {
		t.Error("no pending authentication was issued, so the correct password led nowhere " +
			"at all rather than to the code prompt")
	}
}

// TestAnOutstandingPromptStopsTheSession.
//
// The interlock lives in completeSignIn, which the package comment says exists
// so that "a new authentication method cannot forget it". That claim is about
// the wiring, so only a journey test can check it.
func TestAnOutstandingPromptStopsTheSession(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()

	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.prompts (org_id, slug, title, body, fields, once, enabled)
		VALUES ($1::uuid, 'terms-'||substr(gen_random_uuid()::text,1,8), 'Terms', 'Agree',
		        '[{"name":"agree","type":"checkbox","label":"I agree","required":true}]'::jsonb,
		        true, true)`, f.orgID); err != nil {
		t.Skipf("could not create a prompt in this schema: %v", err)
	}

	got := f.attempt(t, f.email, signInTestPassword)
	if got.signedIn() {
		t.Fatal("a session was issued with a prompt outstanding; the notice is one " +
			"nobody agreed to")
	}
	if n := f.sessionRows(t); n != 0 {
		t.Fatalf("%d session row(s) created with a prompt outstanding", n)
	}
}

// TestAFlaggedPasswordStopsTheSession -- the credential is expired, breached, or
// set by an administrator, and must be changed before anything else happens.
func TestAFlaggedPasswordStopsTheSession(t *testing.T) {
	f := newSignInFixture(t)

	if _, err := f.pool.Exec(context.Background(), `
		UPDATE core.password_credentials
		SET must_change = true, must_change_reason = 'set by an administrator'
		WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}

	got := f.attempt(t, f.email, signInTestPassword)
	if got.signedIn() {
		t.Fatal("a session was issued on a credential flagged for change")
	}
	if n := f.sessionRows(t); n != 0 {
		t.Fatalf("%d session row(s) created on a flagged credential", n)
	}
}

// TestADeactivatedUserCannotSignIn. The status check is inside the lookup query
// rather than a separate branch, which is the right place for it -- and exactly
// the kind of thing that is silently lost in a refactor with nothing asserting
// on it.
func TestADeactivatedUserCannotSignIn(t *testing.T) {
	f := newSignInFixture(t)

	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}

	got := f.attempt(t, f.email, signInTestPassword)
	if got.signedIn() {
		t.Fatal("a deactivated account signed in with a correct password")
	}
	if n := f.sessionRows(t); n != 0 {
		t.Fatalf("a deactivated account created %d session row(s)", n)
	}
}

// TestTheSessionCookieIsNotReadableByScript pins the attributes on the one
// cookie that is worth stealing.
func TestTheSessionCookieIsNotReadableByScript(t *testing.T) {
	f := newSignInFixture(t)

	get := httptest.NewRequest(http.MethodGet, "/login", nil)
	grec := httptest.NewRecorder()
	f.srv.handleLoginGet(grec, get)
	var csrfCookie string
	for _, c := range grec.Result().Cookies() {
		if c.Name == CSRFCookieName {
			csrfCookie = c.Value
		}
	}
	const marker = `name="` + csrfFormField + `" value="`
	body := grec.Body.String()
	i := strings.Index(body, marker)
	rest := body[i+len(marker):]
	csrfField := rest[:strings.Index(rest, `"`)]

	form := url.Values{
		"username": {f.email}, "password": {signInTestPassword},
		csrfFormField: {csrfField},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfCookie})
	rec := httptest.NewRecorder()
	f.srv.rateLimitedLogin(rec, req)

	var found *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			found = c
		}
	}
	if found == nil {
		t.Fatal("no session cookie was set")
	}
	if !found.HttpOnly {
		t.Error("the session cookie is readable by script")
	}
	if !found.Secure {
		t.Error("the session cookie is sent over plaintext")
	}
	if found.SameSite != http.SameSiteLaxMode && found.SameSite != http.SameSiteStrictMode {
		t.Errorf("the session cookie has SameSite=%v", found.SameSite)
	}
}

// csrfValuePattern matches the hidden field's value, which changes on every
// render. Long enough not to match ordinary attribute values in the form.
var csrfValuePattern = regexp.MustCompile(`value="[A-Za-z0-9_\-]{20,}"`)

func normaliseCSRF(body string) string {
	return csrfValuePattern.ReplaceAllString(body, `value="TOKEN"`)
}
