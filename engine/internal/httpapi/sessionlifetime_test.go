package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// How long a session lasts, and how long unused (5.09). Time is moved by
// shifting the session's own timestamps back together, which is what waiting
// would have done to them.

// sessionDeadlines reads a session's two deadlines and last use, as seconds
// from now.
func sessionDeadlines(t *testing.T, f *signInFixture, sid string) (notAfter, absolute, lastSeen float64) {
	t.Helper()
	if err := f.pool.QueryRow(context.Background(), `
		SELECT extract(epoch FROM not_after - now()), extract(epoch FROM absolute_not_after - now()),
		       extract(epoch FROM last_seen_at - now())
		  FROM core.sessions WHERE sid = $1`, sid).Scan(&notAfter, &absolute, &lastSeen); err != nil {
		t.Fatal(err)
	}
	return
}

// shiftSession moves every timestamp of a session back by d, as if d had passed
// without it being used.
func shiftSession(t *testing.T, f *signInFixture, sid string, d time.Duration) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE core.sessions SET auth_time = auth_time - $2::interval, created_at = created_at - $2::interval,
		       last_seen_at = last_seen_at - $2::interval, not_after = not_after - $2::interval,
		       absolute_not_after = absolute_not_after - $2::interval
		 WHERE sid = $1`, sid, d.String()); err != nil {
		t.Fatal(err)
	}
}

func limitSessions(t *testing.T, f *signInFixture, lifetime, idle time.Duration) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, _, _, err := store.SetSessionLifetimes(ctx, tx, f.orgID, lifetime, idle); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func signedIn(t *testing.T, f *signInFixture, cookie string) bool {
	t.Helper()
	rec := accountGET(f, cookie, "/account")
	return rec.Code == http.StatusOK && !strings.HasPrefix(rec.Header().Get("Location"), "/login")
}

func TestAnUnusedSessionEndsAndAUsedOneDoesNot(t *testing.T) {
	f, cookie := enrolFixture(t)
	ctx := context.Background()
	sid, _, err := store.ResolveSessionCookie(ctx, f.pool, store.HashToken(cookie))
	if err != nil || sid == "" {
		t.Fatalf("the fixture's session: %v", err)
	}
	if na, abs, _ := sessionDeadlines(t, f, sid); abs < 11*3600 || na < abs-5 {
		t.Fatalf("a new session's deadlines are %.0fs and %.0fs, want twelve hours with no idle limit", na, abs)
	}

	// An idle limit applies to the session already signed in, at once.
	limitSessions(t, f, 12*time.Hour, 5*time.Minute)
	if na, _, _ := sessionDeadlines(t, f, sid); na > 5*60+5 || na < 5*60-60 {
		t.Fatalf("after a five-minute idle limit the session lasts %.0fs more", na)
	}

	// Used four minutes on: still signed in, and the deadline moves.
	shiftSession(t, f, sid, 4*time.Minute)
	if !signedIn(t, f, cookie) {
		t.Fatal("a session used four minutes after its last use was refused under a five-minute limit")
	}
	if na, _, seen := sessionDeadlines(t, f, sid); na < 4*60 || seen < -5 {
		t.Errorf("using the session did not move its deadline: %.0fs left, last seen %.0fs ago", na, -seen)
	}

	// Then six minutes unused: refused.
	shiftSession(t, f, sid, 6*time.Minute)
	if signedIn(t, f, cookie) {
		t.Fatal("a session unused for six minutes was accepted under a five-minute idle limit")
	}

	// A sign-in under the limits starts with them.
	clearSignInBucket(t, f.pool)
	fresh := f.signInAndReturnCookie(t)
	sid, _, err = store.ResolveSessionCookie(ctx, f.pool, store.HashToken(fresh))
	if err != nil || sid == "" {
		t.Fatalf("signing in again: %v", err)
	}
	if na, abs, _ := sessionDeadlines(t, f, sid); na > 5*60+5 || abs < 11*3600 {
		t.Errorf("a new session lasts %.0fs unused and %.0fs in all, want five minutes and twelve hours", na, abs)
	}
}

// Use moves the idle deadline and never the absolute one, and the database
// refuses a deadline past it whoever writes it.
func TestUseNeverExtendsASessionPastItsLifetime(t *testing.T) {
	f, cookie := enrolFixture(t)
	ctx := context.Background()
	sid, _, err := store.ResolveSessionCookie(ctx, f.pool, store.HashToken(cookie))
	if err != nil || sid == "" {
		t.Fatalf("the fixture's session: %v", err)
	}
	limitSessions(t, f, time.Hour, 30*time.Minute)
	// In use the whole hour, the last time two minutes ago, a minute of its
	// lifetime left.
	if _, err := f.pool.Exec(ctx, `UPDATE core.sessions SET auth_time = now() - interval '59 minutes',
		absolute_not_after = now() + interval '1 minute', last_seen_at = now() - interval '2 minutes',
		not_after = now() + interval '1 minute' WHERE sid = $1`, sid); err != nil {
		t.Fatal(err)
	}
	if !signedIn(t, f, cookie) {
		t.Fatal("a session with a minute of its lifetime left was refused")
	}
	if na, abs, _ := sessionDeadlines(t, f, sid); na > abs+0.001 || abs > 61 {
		t.Errorf("use moved the deadline to %.0fs, past the lifetime's %.0fs", na, abs)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.sessions SET not_after = absolute_not_after + interval '1 second'
		WHERE sid = $1`, sid); err == nil {
		t.Error("the database accepted a session deadline past its lifetime")
	}

	// A longer lifetime does not lengthen a session already signed in.
	limitSessions(t, f, 24*time.Hour, 0)
	if _, abs, _ := sessionDeadlines(t, f, sid); abs > 61 {
		t.Errorf("a longer lifetime lengthened a live session to %.0fs", abs)
	}
}

// An application refreshing a token under the session is a use of it.
func TestARefreshIsAUseOfItsSession(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	rt := f.firstRefreshToken(t)
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.SetSessionLifetimes(ctx, tx, f.orgID, 12*time.Hour, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.sessions SET last_seen_at = now() - interval '20 minutes',
		not_after = least(absolute_not_after, now() + interval '10 minutes') WHERE sid = $1`, f.sid); err != nil {
		t.Fatal(err)
	}
	if status, body := f.refreshWith(t, rt, ""); status != http.StatusOK {
		t.Fatalf("refresh: %d %v", status, body)
	}
	var left float64
	if err := f.pool.QueryRow(ctx, `SELECT extract(epoch FROM not_after - now()) FROM core.sessions WHERE sid = $1`,
		f.sid).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left < 25*60 {
		t.Errorf("after a refresh the session has %.0fs left, want the thirty-minute idle limit again", left)
	}
}
