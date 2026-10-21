package mfa

import (
	"testing"
	"time"
)

// Plausible decides whether a wrong code is charged to the authenticator. If it
// were stricter than Verify, there would be submissions Verify still checks
// that nothing counts -- free guesses. So every input Plausible refuses must
// also be one Verify can never accept.
func TestPlausibleIsNeverStricterThanVerify(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(59, 0)
	right := Code(secret, Counter(now, DefaultPeriod), DefaultDigits)

	for in, want := range map[string]bool{
		right:             true,
		" " + right + " ": true,
		"000000":          true,
		"12345":           false,
		"1234567":         false,
		"+12345":          false,
		"-12345":          false,
		"12 345":          false,
		"\U0000FF11\U0000FF12\U0000FF13\U0000FF14\U0000FF15\U0000FF16": false, // fullwidth digits
		"": false,
	} {
		if got := Plausible(in, DefaultDigits); got != want {
			t.Errorf("Plausible(%q) = %v, want %v", in, got, want)
		}
		if !Plausible(in, DefaultDigits) {
			if _, err := def.Verify(secret, in, now, DefaultSkew, 0); err == nil {
				t.Errorf("Verify accepted %q, which Plausible says cannot match", in)
			}
		}
	}
	if _, err := def.Verify(secret, " "+right+" ", now, DefaultSkew, 0); err != nil {
		t.Errorf("the right code with surrounding space was refused: %v", err)
	}
}
