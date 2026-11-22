package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// A passkey whose signature counter did not advance is refused by default, and
// admitted (still recorded) when the organisation turns the refusal off. The
// refusal hung on a configuration field nothing assigned, so it could not be
// switched on at all (2.06).
func TestACounterThatDidNotAdvanceIsRefusedByDefault(t *testing.T) {
	j := newPasskeyJourney(t)
	ctx := context.Background()
	session := &http.Cookie{Name: SessionCookieName, Value: j.signInAndReturnCookie(t)}
	cred := j.register(t, session)
	t.Cleanup(func() {
		_, _ = j.pool.Exec(context.Background(), `DELETE FROM core.webauthn_policy WHERE org_id = $1::uuid`, j.orgID)
	})

	// A first sign-in moves the stored counter to 1.
	if _, _, ok := j.sessionFor(t, j.signIn(t, cred)); !ok {
		t.Fatal("the first sign-in failed")
	}
	replayCount := func(p *ceremonyParts) { p.Count = 1 } // what a copy of the key would send

	rec := j.signIn(t, cred, replayCount)
	if _, _, ok := j.sessionFor(t, rec); ok {
		t.Fatal("a counter that did not advance signed in with no policy set, where the default is to refuse")
	}
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "copied") {
		t.Errorf("the refusal was %d %s", rec.Code, rec.Body)
	}

	tx, err := j.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetWebAuthnPolicy(ctx, tx, j.orgID, store.WebAuthnPolicy{
		Conveyance: "none", RefuseCloned: false}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := j.sessionFor(t, j.signIn(t, cred, replayCount)); !ok {
		t.Error("with the refusal turned off, the regression did not sign in")
	}
	var recorded int
	if err := j.pool.QueryRow(ctx, `SELECT count(*) FROM core.audit_events
		WHERE event_type = 'mfa.passkey_counter_regression' AND subject_id = $1::uuid`, j.userID).
		Scan(&recorded); err != nil || recorded < 2 {
		t.Errorf("%d regressions recorded (%v), want both", recorded, err)
	}
}
