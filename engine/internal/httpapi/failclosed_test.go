package httpapi

import (
	"context"
	"fmt"
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
	"signari.dev/engine/internal/store"
)

// The current-password check at /account/password was unmetered, so a stolen
// session cookie could guess the account's password there without limit.
func TestTheCurrentPasswordCheckSpendsTheSignInBudget(t *testing.T) {
	f, cookie := enrolFixture(t)
	clearOfWindowEdge(t, signInPerIPWindow)
	clearSignInBucket(t, f.pool)

	hash := func() string {
		t.Helper()
		var h string
		if err := f.pool.QueryRow(context.Background(),
			`SELECT hash FROM core.password_credentials WHERE user_id = $1::uuid`, f.userID).Scan(&h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	before := hash()

	change := func(current string) string {
		t.Helper()
		rec := f.formPost(t, cookie, "/account/password", "/account/password", url.Values{
			"current": {current}, "password": {"an-entirely-new-passphrase-2026"},
			"confirm": {"an-entirely-new-passphrase-2026"},
		})
		return rec.Body.String()
	}
	for i := 0; i < signInPerIPLimit; i++ {
		if body := change("a-guess"); strings.Contains(body, "Too many") {
			t.Fatalf("refused after only %d wrong guesses", i)
		}
	}
	if body := change(signInTestPassword); !strings.Contains(body, "Too many") {
		t.Fatalf("after %d wrong current passwords the right one still changed the password",
			signInPerIPLimit)
	}
	if hash() != before {
		t.Fatal("the refused change still replaced the password")
	}
}

// People with a username and no email shared one current-password bucket, keyed
// "signin:fail:user:" with nothing after it, in every organisation: one
// person's wrong guesses stopped all the others changing their passwords.
func TestAnAccountWithoutAnEmailHasACurrentPasswordBudgetOfItsOwn(t *testing.T) {
	f, cookie := enrolFixture(t)
	clearOfWindowEdge(t, signInPerAccountWindow)
	clearSignInBucket(t, f.pool)
	ctx := context.Background()
	username := fmt.Sprintf("nomail-%d", time.Now().UnixNano())
	if _, err := f.pool.Exec(ctx,
		`UPDATE core.users SET email = NULL, username = $2 WHERE id = $1::uuid`, f.userID, username); err != nil {
		t.Fatal(err)
	}
	fill := func(key string) {
		t.Helper()
		t.Cleanup(func() {
			_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.rate_limits WHERE bucket_key = $1`, key)
		})
		for i := 0; i < signInPerAccountLimit; i++ {
			if _, err := store.AllowRate(ctx, f.pool, key, signInPerAccountLimit, signInPerAccountWindow); err != nil {
				t.Fatal(err)
			}
		}
	}
	change := func(newPassword string) string {
		t.Helper()
		return f.formPost(t, cookie, "/account/password", "/account/password", url.Values{
			"current": {signInTestPassword}, "password": {newPassword}, "confirm": {newPassword},
		}).Body.String()
	}

	// Its own budget -- the one the sign-in form charges for its username --
	// binds. First, because a refusal changes nothing and keeps the session.
	own := "signin:fail:user:" + username
	fill(own)
	if body := change("yet-another-new-passphrase-2026"); !strings.Contains(body, "Too many") {
		t.Fatal("an email-less account whose own budget is spent could still try its current password")
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM core.rate_limits WHERE bucket_key = $1`, own); err != nil {
		t.Fatal(err)
	}

	// Somebody else without an email spent the bucket they all used to share.
	fill("signin:fail:user:")
	if body := change("an-entirely-new-passphrase-2026"); strings.Contains(body, "Too many") {
		t.Fatal("another email-less account's wrong guesses stopped this one changing its password")
	}
}

// The shape both fail-open limiters had: the result read only when the call
// succeeded, so an error fell through to "allowed". Banned in this package.
func TestNoLimiterTreatsAnErrorAsAllowed(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	failOpen := regexp.MustCompile(`(?s)(?:AllowRate|CountRate)\([^;{]*\);\s*\w+\s*==\s*nil\s*&&`)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if failOpen.Match(b) {
			t.Errorf("%s reads a rate limit only when the call succeeded, so a database "+
				"error lets the request through; refuse on the error instead", e.Name())
		}
	}
}

// A limiter that cannot reach its table refuses. Signup used to wave the
// request through, so a fault in the limiter was an unlimited window for the
// flood it exists to stop. The fault here is real: the pool runs as the
// console's role, which has no privilege on core at all.
func TestSignupRefusesWhenItsLimiterCannotBeRead(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_admin")
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	set, _ := keys.NewSet(active)
	srv, err := New(oidc.Config{Issuer: "https://failclosed.example", Keys: set, AllowInsecureIssuer: true},
		pool, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	token := strings.Repeat("A", 43) // the shape of a CSRF value: 32 bytes, base64url
	form := url.Values{csrfFormField: {token}, "email": {"someone@example.test"},
		"password": {"a-long-enough-signup-passphrase"}}
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	rec := httptest.NewRecorder()
	srv.handleSignupPost(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("with its limiter unreadable, signup answered %d, want 503: %.200s", rec.Code, rec.Body.String())
	}
}
