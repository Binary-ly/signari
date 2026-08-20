package sdjwt

import (
	"testing"
	"time"
)

// The guarantee the handler cannot test, because there the clock is not an
// argument: every instant inside one period must round to the same value.
//
// That is what makes a batch agree by construction. If rounding were replaced by
// jitter, or applied per credential from separate clock readings, credentials
// issued seconds apart could still differ — and a difference is exactly the
// signal RFC 9901 §10.1 is removing.
func TestEveryInstantInAPeriodRoundsToOneValue(t *testing.T) {
	const lifetime = 30 * 24 * time.Hour // period: one day
	base := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)

	want := RoundForUnlinkability(base, lifetime)
	if !want.Equal(base) {
		t.Fatalf("a day boundary did not round to itself: %v", want)
	}
	for _, off := range []time.Duration{
		time.Nanosecond, time.Second, time.Minute, time.Hour,
		12 * time.Hour, 23*time.Hour + 59*time.Minute + 59*time.Second,
	} {
		if got := RoundForUnlinkability(base.Add(off), lifetime); !got.Equal(want) {
			t.Errorf("an instant %s into the day rounded to %v, want %v; two holders "+
				"issued on the same day are distinguishable by their credentials",
				off, got, want)
		}
	}
	// And the next period is a different value, or rounding would be a constant
	// and every credential this issuer ever minted would claim the same date.
	if got := RoundForUnlinkability(base.Add(24*time.Hour), lifetime); got.Equal(want) {
		t.Error("the following day rounded to the same instant")
	}
}

// Rounding down moves `exp` down with it, so a period that is coarse relative to
// the lifetime hands out a credential that has already expired.
//
// periodFor bounds the period at an eighth of the lifetime to make that
// impossible rather than unlikely. This checks the bound holds across the range
// where the period changes -- around eight minutes, eight hours and eight days,
// which is where an off-by-one in the selection would show.
func TestARoundedCredentialIsNeverBornExpiredAndNeverOutlivesItsLifetime(t *testing.T) {
	lifetimes := []time.Duration{
		time.Minute, 8 * time.Minute, 10 * time.Minute, time.Hour,
		7 * time.Hour, 8 * time.Hour, 9 * time.Hour, 23 * time.Hour,
		24 * time.Hour, 7 * 24 * time.Hour, 8 * 24 * time.Hour,
		30 * 24 * time.Hour, 365 * 24 * time.Hour,
	}
	// Offsets chosen to land just inside and just outside each period boundary.
	offsets := []time.Duration{
		0, time.Second, 59 * time.Second, time.Minute,
		59 * time.Minute, time.Hour, 23 * time.Hour,
		23*time.Hour + 59*time.Minute + 59*time.Second,
	}
	base := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)

	for _, life := range lifetimes {
		for _, off := range offsets {
			now := base.Add(off)
			exp := RoundForUnlinkability(now, life).Add(life)

			if !exp.After(now) {
				t.Errorf("lifetime %s issued at %s expires at %s, which is not after "+
					"issuance: the holder receives a credential that is already dead",
					life, now.Format(time.RFC3339), exp.Format(time.RFC3339))
			}
			if exp.After(now.Add(life)) {
				t.Errorf("lifetime %s issued at %s expires at %s, later than the "+
					"configured lifetime allows: rounding must not extend validity",
					life, now.Format(time.RFC3339), exp.Format(time.RFC3339))
			}
			// The credential must keep most of its life, or "rounded" becomes a
			// quiet way of shortening every credential the deployment issues.
			if got := exp.Sub(now); got < life*7/8 {
				t.Errorf("lifetime %s issued at %s keeps only %s, under seven eighths",
					life, now.Format(time.RFC3339), got)
			}
		}
	}
}

// RFC 9901 §9.7 names `aud` security critical. The list this package started
// from was the SD-JWT VC profile's, which does not.
func TestTheAudienceCannotBeSelectivelyDisclosed(t *testing.T) {
	if _, err := NewDisclosure("aud", "https://verifier.example"); err == nil {
		t.Error("a disclosure was built for `aud`; §9.7 makes it security critical, " +
			"and a verifier that cannot see the audience cannot tell the credential " +
			"was addressed to somebody else")
	}
	// Through the path issuance actually uses, not only the constructor.
	if _, _, err := Payload(map[string]any{"iss": "https://issuer.example"},
		map[string]any{"aud": "https://verifier.example"}); err == nil {
		t.Error("Payload accepted `aud` as selectively disclosable")
	}
	// Every name §9.7 lists, so the list cannot be trimmed without a failure.
	for _, name := range []string{"iss", "aud", "exp", "nbf", "cnf"} {
		if !RedList[name] {
			t.Errorf("§9.7 names %q security critical and it is not on the red list", name)
		}
	}
}
