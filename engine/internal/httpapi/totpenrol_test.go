package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/store"
)

// TOTP enrolment, and the rule it broke: a GET may not change an account.
//
// Opening /account/mfa/totp used to overwrite the user's confirmed TOTP
// credential with a fresh, unconfirmed one. The session cookie is SameSite=Lax,
// which a browser sends on any top-level navigation from another site, so a
// link anywhere on the web -- followed by a signed-in user whose only second
// factor was TOTP -- turned that factor off.

// enrolFixture is a signed-in user able to hold sealed secrets.
func enrolFixture(t *testing.T) (*signInFixture, string) {
	t.Helper()
	f := newSignInFixture(t)
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root
	cookie := f.signInAndReturnCookie(t)
	if cookie == "" {
		t.Fatal("the fixture user could not sign in")
	}
	return f, cookie
}

// giveTOTP leaves the fixture user with a confirmed credential and returns it.
func giveTOTP(t *testing.T, f *signInFixture) []byte {
	t.Helper()
	ctx := context.Background()
	secret, _, err := mfa.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.StartTOTPEnrolment(ctx, tx, f.userID, f.orgID, secret,
		mfa.DefaultDigits, mfa.DefaultPeriod, f.srv.cfg.Root); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteTOTPEnrolment(ctx, tx, f.userID, 0); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return secret
}

func totpState(t *testing.T, f *signInFixture) (sealed []byte, confirmed bool) {
	t.Helper()
	var at *time.Time
	if err := f.pool.QueryRow(context.Background(), `
		SELECT secret_enc, confirmed_at FROM core.totp_credentials WHERE user_id = $1::uuid`,
		f.userID).Scan(&sealed, &at); err != nil {
		t.Fatalf("reading the TOTP credential: %v", err)
	}
	return sealed, at != nil
}

func accountGET(f *signInFixture, cookie, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

// THE regression: the GET a cross-site link triggers must leave the factor on.
func TestOpeningTheTOTPPageCannotTurnTheFactorOff(t *testing.T) {
	f, cookie := enrolFixture(t)
	giveTOTP(t, f)
	before, _ := totpState(t, f)

	rec := accountGET(f, cookie, "/account/mfa/totp")
	if rec.Code != http.StatusOK {
		t.Fatalf("the enrolment page gave %d", rec.Code)
	}

	after, confirmed := totpState(t, f)
	if !confirmed || string(after) != string(before) {
		t.Fatal("GET /account/mfa/totp changed the user's confirmed TOTP credential; " +
			"any site can send a signed-in user there with a link")
	}
	has, err := store.HasSecondFactor(context.Background(), f.pool, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatal("GET /account/mfa/totp turned the user's second factor off")
	}
}

// Generating a secret is a state change, so it must carry the CSRF token.
func TestStartingAnEnrolmentNeedsTheCSRFToken(t *testing.T) {
	f, cookie := enrolFixture(t)

	r := httptest.NewRequest(http.MethodPost, "/account/mfa/totp/start", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a start with no CSRF token gave %d, want 403", rec.Code)
	}

	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM core.totp_enrolments WHERE user_id = $1::uuid`, f.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("a forged start request stored an enrolment")
	}
}

var csrfValue = regexp.MustCompile(`name="` + regexp.QuoteMeta(csrfFormField) + `" value="([^"]+)"`)

// The whole journey through the real routes: introduction, start, confirm.
func TestReEnrollingReplacesTheFactorOnlyOnceTheNewOneIsProved(t *testing.T) {
	f, cookie := enrolFixture(t)
	original := giveTOTP(t, f)
	ctx := context.Background()

	page := accountGET(f, cookie, "/account/mfa/totp")
	m := csrfValue.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatal("the introduction carries no CSRF field")
	}
	var csrfCookie string
	for _, c := range page.Result().Cookies() {
		if c.Name == CSRFCookieName {
			csrfCookie = c.Value
		}
	}
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		form.Set(csrfFormField, m[1])
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfCookie})
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		return rec
	}

	if rec := post("/account/mfa/totp/start", url.Values{}); rec.Code != http.StatusOK {
		t.Fatalf("starting the enrolment gave %d: %s", rec.Code, rec.Body.String())
	}

	// Until the new secret is proved, the old authenticator is still the factor.
	if sealed, confirmed := totpState(t, f); !confirmed || len(sealed) == 0 {
		t.Fatal("starting a re-enrolment disturbed the confirmed credential")
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := store.LoadTOTPEnrolment(ctx, tx, f.userID, f.srv.cfg.Root)
	_ = tx.Rollback(ctx)
	if err != nil {
		t.Fatalf("no enrolment after starting one: %v", err)
	}

	// A wrong code changes nothing.
	if rec := post("/account/mfa/totp", url.Values{"code": {"000000"}}); rec.Code != http.StatusOK {
		t.Fatalf("a wrong confirmation code gave %d", rec.Code)
	}
	tx, _ = f.pool.Begin(ctx)
	still, err := store.LoadTOTP(ctx, tx, f.userID, f.srv.cfg.Root)
	_ = tx.Rollback(ctx)
	if err != nil || string(still.Secret) != string(original) {
		t.Fatal("a wrong confirmation code replaced the authenticator")
	}

	code := mfa.Code(pending.Secret, mfa.Counter(time.Now(), mfa.DefaultPeriod), mfa.DefaultDigits)
	if rec := post("/account/mfa/totp", url.Values{"code": {code}}); rec.Code != http.StatusOK {
		t.Fatalf("confirming with the right code gave %d: %s", rec.Code, rec.Body.String())
	}
	tx, _ = f.pool.Begin(ctx)
	now, err := store.LoadTOTP(ctx, tx, f.userID, f.srv.cfg.Root)
	_ = tx.Rollback(ctx)
	if err != nil || string(now.Secret) != string(pending.Secret) || !now.Confirmed {
		t.Fatal("a proved re-enrolment did not become the confirmed credential")
	}
}

// Every self-service page reached by GET must leave the account exactly as it
// found it -- the general form of the TOTP defect.
//
// The rule is scoped to /account because that is where a cross-site link
// reaches a signed-in person's own credentials; protocol endpoints such as
// /authorize write by design and are defended by other means. The routes come
// from server.go, so a new account page is covered the day it is added.
func TestNoAccountPageChangesTheAccountOnAGet(t *testing.T) {
	if os.Getenv("SIGNARI_TEST_DSN") == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	f, cookie := enrolFixture(t)
	giveTOTP(t, f)
	ctx := context.Background()

	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, m := range regexp.MustCompile(`HandleFunc\("GET (/account[^"]*)"`).FindAllStringSubmatch(string(src), -1) {
		paths = append(paths, regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(m[1], "nonexistent"))
	}
	if len(paths) < 8 {
		t.Fatalf("found only %d GET /account routes in server.go; the pattern is not matching", len(paths))
	}

	// Every core table that holds rows about a user, fingerprinted for this one.
	rows, err := f.pool.Query(ctx, `
		SELECT c.table_name FROM information_schema.columns c
		  JOIN information_schema.tables t
		    ON t.table_schema = c.table_schema AND t.table_name = c.table_name
		 WHERE c.table_schema = 'core' AND c.column_name = 'user_id' AND t.table_type = 'BASE TABLE'
		 ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	rows.Close()

	fingerprint := func() map[string]string {
		out := map[string]string{}
		for _, tbl := range tables {
			var h *string
			if err := f.pool.QueryRow(ctx, `SELECT md5(string_agg(t::text, '|' ORDER BY t::text))
				FROM core.`+tbl+` t WHERE user_id = $1::uuid`, f.userID).Scan(&h); err != nil {
				t.Fatalf("fingerprinting core.%s: %v", tbl, err)
			}
			if h != nil {
				out[tbl] = *h
			}
		}
		return out
	}

	for _, p := range paths {
		before := fingerprint()
		accountGET(f, cookie, p)
		after := fingerprint()
		for tbl, h := range before {
			if after[tbl] != h {
				t.Errorf("GET %s changed this user's rows in core.%s; a page a link can open "+
					"must not change the account", p, tbl)
			}
		}
		for tbl := range after {
			if _, ok := before[tbl]; !ok {
				t.Errorf("GET %s created rows for this user in core.%s", p, tbl)
			}
		}
	}
}
