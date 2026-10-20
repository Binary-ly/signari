package httpapi

import (
	"context"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

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
		st, err := store.CheckLoginThrottle(ctx, f.pool, f.userID)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	if st := wrong(2); st.Throttled {
		t.Fatalf("two wrong passwords under the default of three free were delayed %s", st.RetryAfter)
	}
	set(1, 0)
	if st := wrong(2); !st.Throttled {
		t.Fatal("two wrong passwords under an organisation allowing one were not delayed")
	}
	// The ceiling: twelve failures recorded (a delayed attempt is refused
	// before it is counted, so the form alone would never get this far) is
	// 2^10 s uncapped, a minute here.
	set(0, time.Minute)
	if err := store.ClearLoginThrottle(ctx, f.pool, f.userID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		if err := store.RecordLoginFailure(ctx, f.pool, f.userID); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.CheckLoginThrottle(ctx, f.pool, f.userID)
	if err != nil {
		t.Fatal(err)
	}
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
