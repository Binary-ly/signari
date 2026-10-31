package httpapi

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// throttleOf reads what the delay stands at for the fixture's person, spending
// nothing.
func throttleOf(t *testing.T, f *signInFixture) store.ThrottleState {
	t.Helper()
	var st store.ThrottleState
	var wait float64
	if err := f.pool.QueryRow(context.Background(), `
		SELECT failed_attempts, COALESCE(EXTRACT(EPOCH FROM throttled_until - now()), 0)::float8
		  FROM core.password_credentials WHERE user_id = $1::uuid`, f.userID).Scan(&st.Failures, &wait); err != nil {
		t.Fatal(err)
	}
	st.Throttled = wait > 0
	st.RetryAfter = time.Duration(wait * float64(time.Second))
	return st
}

// A burst of guesses all read the throttle before any of them was recorded, so
// every one of them got a password hash and the only bound was how many the server
// would run at once. The guess is spent before it is checked, in the statement
// that decides, so a burst at a delayed account gets one through and no more.
func TestABurstOfGuessesCannotOutrunTheDelay(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	// Past the free attempts, so the first of the burst earns a delay of a size no
	// slow machine outlasts.
	if _, err := f.pool.Exec(ctx, `UPDATE core.password_credentials
		SET failed_attempts = 12, last_failure_at = now(), throttled_until = NULL WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	const burst = 16
	var through atomic.Int32
	var wg sync.WaitGroup
	for range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := store.ReserveLoginAttempt(ctx, f.pool, f.userID)
			if err != nil {
				t.Error(err)
				return
			}
			if !st.Throttled {
				through.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := through.Load(); got != 1 {
		t.Errorf("%d of %d simultaneous guesses got a password check", got, burst)
	}
	if st := throttleOf(t, f); st.Failures != 13 {
		t.Errorf("the count stands at %d: a refused guess must not be charged on top", st.Failures)
	}
}

// The right password gives back what the attempt was charged, so a person is never
// delayed by having signed in, and the delay a wrong one earns is LoginDelayFor's.
func TestAGuessIsChargedUpFrontAndARightOneRefunded(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	clearSignInBucket(t, f.pool)
	if got := f.attempt(t, f.email, signInTestPassword); !got.signedIn() {
		t.Fatalf("signing in: %+v", got)
	}
	if st := throttleOf(t, f); st.Failures != 0 || st.Throttled {
		t.Errorf("after signing in the count stands at %+v", st)
	}
	for _, c := range []struct {
		failures, free int
		longest        time.Duration
	}{{3, 3, 15 * time.Minute}, {4, 3, 15 * time.Minute}, {7, 3, 15 * time.Minute}, {11, 1, time.Minute}, {60, 3, time.Hour}} {
		if _, err := f.pool.Exec(ctx, `UPDATE core.organizations SET login_free_attempts = $2, login_max_delay_s = $3
			WHERE id = $1::uuid`, f.orgID, c.free, int(c.longest.Seconds())); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(ctx, `UPDATE core.password_credentials
			SET failed_attempts = $2, last_failure_at = now(), throttled_until = NULL WHERE user_id = $1::uuid`,
			f.userID, c.failures); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ReserveLoginAttempt(ctx, f.pool, f.userID); err != nil {
			t.Fatal(err)
		}
		want := store.LoginDelayFor(c.failures+1, c.free, c.longest)
		if got := throttleOf(t, f).RetryAfter; got > want || got < want-5*time.Second {
			t.Errorf("after %d failures of %d free, capped at %s: a delay of %s, wanting %s",
				c.failures+1, c.free, c.longest, got, want)
		}
	}
	// Past the decay the count starts again, whatever it stood at.
	if _, err := f.pool.Exec(ctx, `UPDATE core.password_credentials
		SET failed_attempts = 50, last_failure_at = now() - $2::interval, throttled_until = now() + interval '1 hour'
		WHERE user_id = $1::uuid`, f.userID, (store.FailureDecay + time.Minute).String()); err != nil {
		t.Fatal(err)
	}
	st, err := store.ReserveLoginAttempt(ctx, f.pool, f.userID)
	if err != nil || st.Throttled {
		t.Fatalf("after the decay: %+v, %v", st, err)
	}
	if got := throttleOf(t, f); got.Failures != 1 {
		t.Errorf("after the decay the count stands at %d, wanting 1", got.Failures)
	}
}

// The sign-in delay is the organisation's (4.06): how many wrong passwords
// are free, and how long the delay grows to. They were constants.
func TestTheSignInDelayIsTheOrganisations(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	set := func(free int, max time.Duration) {
		t.Helper()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := store.SetLoginThrottle(ctx, tx, f.orgID, free, max); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	wrong := func(n int) store.ThrottleState {
		t.Helper()
		if err := store.ClearLoginThrottle(ctx, f.pool, f.userID); err != nil {
			t.Fatal(err)
		}
		clearSignInBucket(t, f.pool)
		for i := 0; i < n; i++ {
			f.attempt(t, f.email, "not the password")
		}
		return throttleOf(t, f)
	}

	if st := wrong(2); st.Throttled {
		t.Fatalf("two wrong passwords under the default of three free were delayed %s", st.RetryAfter)
	}
	set(1, 0)
	if st := wrong(2); !st.Throttled {
		t.Fatal("two wrong passwords under an organisation allowing one were not delayed")
	}
	// The ceiling: twelve failures (a delayed attempt is refused before it is
	// counted, so the form alone would never get this far) is 2^10 s uncapped, a
	// minute here.
	set(0, time.Minute)
	if err := store.ClearLoginThrottle(ctx, f.pool, f.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.password_credentials SET failed_attempts = 11, last_failure_at = now()
		WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveLoginAttempt(ctx, f.pool, f.userID); err != nil {
		t.Fatal(err)
	}
	st := throttleOf(t, f)
	if !st.Throttled || st.RetryAfter > time.Minute || st.RetryAfter < 50*time.Second {
		t.Errorf("twelve failures under a one-minute ceiling: delayed %v for %s, want about a minute",
			st.Throttled, st.RetryAfter)
	}
	if err := store.ClearLoginThrottle(ctx, f.pool, f.userID); err != nil {
		t.Fatal(err)
	}
	set(3, 15*time.Minute)

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, bad := range []struct {
		free int
		max  time.Duration
	}{{21, 0}, {-1, 0}, {0, 30 * time.Second}, {0, 25 * time.Hour}} {
		if err := store.SetLoginThrottle(ctx, tx, f.orgID, bad.free, bad.max); err == nil {
			t.Errorf("free %d, ceiling %s was accepted", bad.free, bad.max)
		}
	}
}
