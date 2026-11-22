package store

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// A consent's lifetime (5.22).

func consentFixture(t *testing.T, lifetime *int) (userID, clientID string, scopes func() []string,
	record func(...string), age func(time.Duration)) {
	t.Helper()
	ctx := context.Background()
	_, userID, clientID, _ = fixture(t, connect(t))
	pool := rateTestPool(t)
	if _, err := pool.Exec(ctx, `UPDATE core.clients SET consent_lifetime_s = $2 WHERE client_id = $1`, clientID, lifetime); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM core.consents WHERE user_id = $1::uuid`, userID)
	})
	scopes = func() []string {
		t.Helper()
		var s []string
		if err := pool.QueryRow(ctx, `SELECT scopes FROM core.consents WHERE user_id = $1::uuid AND client_id = $2`,
			userID, clientID).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	record = func(s ...string) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := RecordConsent(ctx, tx, userID, clientID, s); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	age = func(d time.Duration) {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE core.consents SET granted_at = now() - make_interval(secs => $3)
			WHERE user_id = $1::uuid AND client_id = $2`, userID, clientID, int(d.Seconds())); err != nil {
			t.Fatal(err)
		}
	}
	return userID, clientID, scopes, record, age
}

func TestAConsentPastItsClientsLifetimeIsAskedAgain(t *testing.T) {
	hour := 3600
	userID, clientID, _, record, age := consentFixture(t, &hour)
	pool := rateTestPool(t)
	ctx := context.Background()
	record("email")
	if d, err := CheckConsent(ctx, pool, userID, clientID, []string{"openid", "email"}); err != nil || !d.Granted {
		t.Fatalf("a fresh consent: %+v %v", d, err)
	}
	age(2 * time.Hour)
	d, err := CheckConsent(ctx, pool, userID, clientID, []string{"openid", "email"})
	if err != nil || d.Granted || !slices.Equal(d.Missing, []string{"email"}) {
		t.Errorf("a consent past the client's hour: %+v %v, want email asked again", d, err)
	}
}

func TestAConsentWithoutALifetimeStands(t *testing.T) {
	userID, clientID, scopes, record, age := consentFixture(t, nil)
	pool := rateTestPool(t)
	record("email")
	age(10 * 365 * 24 * time.Hour)
	if d, err := CheckConsent(context.Background(), pool, userID, clientID, []string{"email"}); err != nil || !d.Granted {
		t.Errorf("a consent with no lifetime, ten years on: %+v %v", d, err)
	}
	record("profile")
	if got := scopes(); !slices.Equal(got, []string{"email", "profile"}) {
		t.Errorf("an incremental consent: %v, want email and profile merged", got)
	}
}

// Asked again, the person approves what is shown. Merging into an expired or
// withdrawn consent brought back every scope of the old one behind it.
func TestAConsentGivenAgainDoesNotReviveWhatEnded(t *testing.T) {
	hour := 3600
	userID, clientID, scopes, record, age := consentFixture(t, &hour)
	record("email", "profile", "groups")
	age(2 * time.Hour)
	record("email")
	if got := scopes(); !slices.Equal(got, []string{"email"}) {
		t.Errorf("given again after it expired: %v, want only email", got)
	}

	record("profile")
	ctx := context.Background()
	pool := rateTestPool(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := WithdrawConsent(ctx, tx, userID, clientID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	record("groups")
	if got := scopes(); !slices.Equal(got, []string{"groups"}) {
		t.Errorf("given again after it was withdrawn: %v, want only groups", got)
	}
}

func TestAConsentLifetimeIsBounded(t *testing.T) {
	for d, ok := range map[time.Duration]bool{
		0: true, time.Hour: true, 90 * 24 * time.Hour: true,
		30 * time.Minute: false, 11 * 365 * 24 * time.Hour: false, 90*time.Minute + time.Millisecond: false,
	} {
		err := CheckClientSettings(ClientSettings{ConsentLifetime: &d})
		if (err == nil) != ok || (err != nil && !errors.Is(err, ErrInvalidClientSetting)) {
			t.Errorf("a consent lifetime of %s: %v, want accepted %v", d, err, ok)
		}
	}
}
