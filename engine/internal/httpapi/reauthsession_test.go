package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"signari.dev/engine/internal/store"
)

// ASVS 5.0.0 V7.2.4: "Verify that the application generates a new session token
// on user authentication, including re-authentication, and terminates the
// current session token."
//
// The first half was never in doubt — completeSignIn mints a fresh sid and
// cookie token every time. The second half was missing, and step-up is where it
// bites: a password-only session (acr=1) stayed live for hours after its holder
// re-authenticated into an acr=2 one. Anyone holding the earlier cookie kept a
// working weaker session, and the user re-authenticated precisely because
// something warranted it.
func TestReauthenticationTerminatesTheSupersededSession(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	// A live session, as if the user had already signed in with a password.
	oldCookie, _ := f.signedInCookies(t)

	var oldSID string
	if err := f.pool.QueryRow(ctx,
		`SELECT sid FROM core.sessions WHERE cookie_hash = $1`,
		store.HashToken(oldCookie)).Scan(&oldSID); err != nil {
		t.Fatal(err)
	}

	// Sign in again in the same browser, presenting the old cookie.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	req := newRequestWithSessionCookie(oldCookie)
	rec := newRecorder()
	f.srv.completeSignIn(rec, req, tx, f.userID, f.orgID, []string{"pwd", "otp"}, "")
	if err := tx.Commit(ctx); err != nil {
		// completeSignIn commits its own transaction on the success path; a
		// "tx is closed" here is that, not a failure.
		t.Logf("commit after completeSignIn: %v", err)
	}

	var revokedReason *string
	if err := f.pool.QueryRow(ctx,
		`SELECT revocation_reason FROM core.sessions WHERE sid = $1`, oldSID).
		Scan(&revokedReason); err != nil {
		t.Fatalf("loading the old session: %v", err)
	}
	if revokedReason == nil {
		t.Fatal("the superseded session is still live. Anyone holding its cookie " +
			"keeps a session at the assurance level the user just moved on from — " +
			"which is the session an attacker would be holding, since step-up is " +
			"usually prompted by something suspicious.")
	}
	if *revokedReason != string(store.ReasonReauthenticated) {
		t.Errorf("revocation_reason = %q, want %q", *revokedReason,
			store.ReasonReauthenticated)
	}

	// And the new session is live and distinct.
	var live int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*) FROM core.sessions
		WHERE user_id = $1::uuid AND revoked_at IS NULL AND sid <> $2`,
		f.userID, oldSID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live == 0 {
		t.Error("no live session after re-authentication; terminating the old one " +
			"must not be the only thing that happened")
	}
}

// A user signed in on two devices who re-authenticates on one has not asked to
// be signed out of the other.
//
// The termination is scoped to the session THIS browser presented. Scoping it to
// the user instead would be a defensible product choice and a different one, and
// it would turn every step-up into a global sign-out.
func TestReauthenticationLeavesOtherDevicesAlone(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	thisBrowser, _ := f.signedInCookies(t)
	otherDevice, _ := f.signedInCookies(t)

	var otherSID string
	if err := f.pool.QueryRow(ctx,
		`SELECT sid FROM core.sessions WHERE cookie_hash = $1`,
		store.HashToken(otherDevice)).Scan(&otherSID); err != nil {
		t.Fatal(err)
	}

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	f.srv.completeSignIn(newRecorder(), newRequestWithSessionCookie(thisBrowser),
		tx, f.userID, f.orgID, []string{"pwd"}, "")
	_ = tx.Commit(ctx)

	var reason *string
	if err := f.pool.QueryRow(ctx,
		`SELECT revocation_reason FROM core.sessions WHERE sid = $1`, otherSID).
		Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != nil {
		t.Errorf("the other device's session was terminated (%q); re-authenticating "+
			"on one browser is not a request to sign out everywhere", *reason)
	}
}

// --- helpers ---

func newRequestWithSessionCookie(cookie string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	return req
}

func newRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }
