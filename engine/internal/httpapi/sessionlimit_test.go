package httpapi

import (
	"context"
	"strings"
	"testing"
)

func TestTheDefaultIsUnlimitedSessions(t *testing.T) {
	f := newSignInFixture(t)
	for i := 0; i < 4; i++ {
		out := f.attempt(t, f.email, signInTestPassword)
		if out.sessionCookie == "" {
			t.Fatalf("sign-in %d produced no session under the default policy; "+
				"an unconfigured organisation must not be capped", i+1)
		}
	}
	if n := liveSessions(t, f); n != 4 {
		t.Errorf("live sessions = %d, want 4 under an unlimited default", n)
	}
}

// deny: the credential is correct and the policy refuses anyway.
func TestDenyRefusesTheSignInOnceTheCapIsReached(t *testing.T) {
	f := newSignInFixture(t)
	setSessionLimit(t, f, 2, "deny")

	for i := 0; i < 2; i++ {
		if out := f.attempt(t, f.email, signInTestPassword); out.sessionCookie == "" {
			t.Fatalf("sign-in %d was refused below the cap", i+1)
		}
	}
	// The third is over the cap.
	out := f.attempt(t, f.email, signInTestPassword)
	if out.sessionCookie != "" {
		t.Fatal("a third session was issued under a cap of two")
	}
	if n := liveSessions(t, f); n != 2 {
		t.Errorf("live sessions = %d, want 2: the refusal must not have ended one", n)
	}
	// The refusal must say what happened. Telling somebody their password is
	// wrong when it is right sends them to reset a working credential.
	if !strings.Contains(out.body, "maximum number") {
		t.Errorf("the refusal does not explain the cap; body = %.200s", out.body)
	}
}

// evict_oldest: the newest sign-in wins and the oldest session ends.
func TestEvictOldestMakesRoomAndEndsTheOldestSession(t *testing.T) {
	f := newSignInFixture(t)
	setSessionLimit(t, f, 2, "evict_oldest")

	for i := 0; i < 2; i++ {
		if out := f.attempt(t, f.email, signInTestPassword); out.sessionCookie == "" {
			t.Fatalf("sign-in %d was refused below the cap", i+1)
		}
	}
	if out := f.attempt(t, f.email, signInTestPassword); out.sessionCookie == "" {
		t.Fatal("the third sign-in was refused under evict_oldest; it should have " +
			"made room rather than turning the person away")
	}
	// Still two LIVE. sessionRows counts every row including revoked ones, so
	// after an eviction it reads three — which is the correct history and the
	// wrong measure for a cap that is about what a person can currently use.
	if n := liveSessions(t, f); n != 2 {
		t.Errorf("live sessions = %d, want 2 after an eviction", n)
	}
	// And the eviction is recorded as a policy decision, not as an admin action:
	// nobody decided this about this session in particular.
	var reason string
	if err := f.pool.QueryRow(context.Background(), `
		SELECT revocation_reason FROM core.sessions
		WHERE user_id = $1::uuid AND revoked_at IS NOT NULL
		ORDER BY revoked_at DESC LIMIT 1`, f.userID).Scan(&reason); err != nil {
		t.Fatalf("reading the evicted session: %v", err)
	}
	if reason != "session_limit" {
		t.Errorf("evicted session reason = %q, want session_limit", reason)
	}
}

func setSessionLimit(t *testing.T, f *signInFixture, max int, behaviour string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE core.organizations SET max_concurrent_sessions = $2,
		       session_limit_behaviour = $3 WHERE id = $1::uuid`,
		f.orgID, max, behaviour); err != nil {
		t.Fatalf("setting the session limit: %v", err)
	}
}

// liveSessions counts what the cap actually governs: sessions a person can use
// right now. The fixture's sessionRows counts every row ever written for them,
// revoked ones included, which is the right history and the wrong denominator.
func liveSessions(t *testing.T, f *signInFixture) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM core.sessions
		WHERE user_id = $1::uuid AND revoked_at IS NULL AND not_after > now()`,
		f.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
