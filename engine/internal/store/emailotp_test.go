package store

import (
	"strings"
	"testing"
)

// TestNumericCodeShape. A code that is sometimes five digits because a leading
// zero was dropped is a support ticket, and one that is sometimes seven is a
// bug nobody notices until a user cannot type it.
func TestNumericCodeShape(t *testing.T) {
	seenLeadingZero := false
	for i := 0; i < 3000; i++ {
		c, err := newNumericCode(EmailOTPDigits)
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != EmailOTPDigits {
			t.Fatalf("code %q is %d digits, want %d", c, len(c), EmailOTPDigits)
		}
		if strings.Trim(c, "0123456789") != "" {
			t.Fatalf("code %q is not all digits", c)
		}
		if c[0] == '0' {
			seenLeadingZero = true
		}
	}
	// Leading zeros must survive formatting. If they were being dropped, every
	// code would start 1-9 and one in ten users would be handed a short code.
	if !seenLeadingZero {
		t.Error("no code in 3000 began with 0; leading zeros are being lost")
	}
}

// TestNumericCodeSpreadsAcrossTheRange.
//
// A six-digit code has only a million values, so the distribution IS the
// entropy. This would catch a modulo bias bad enough to matter, or a generator
// stuck near one end.
func TestNumericCodeSpreadsAcrossTheRange(t *testing.T) {
	buckets := make([]int, 10)
	const n = 5000
	for i := 0; i < n; i++ {
		c, err := newNumericCode(EmailOTPDigits)
		if err != nil {
			t.Fatal(err)
		}
		buckets[c[0]-'0']++
	}
	// Each leading digit should appear about n/10 times. A generous band: this
	// is looking for gross skew, not testing the standard library's RNG.
	for d, count := range buckets {
		if count < n/20 || count > n/5 {
			t.Errorf("leading digit %d appeared %d times in %d; the distribution "+
				"is badly skewed", d, count, n)
		}
	}
}

func TestNumericCodeDoesNotRepeatQuickly(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := newNumericCode(EmailOTPDigits)
		if err != nil {
			t.Fatal(err)
		}
		seen[c] = true
	}
	// A million values, 200 draws: collisions are possible but vanishingly
	// unlikely. Anything below this means the generator is not random.
	if len(seen) < 195 {
		t.Errorf("only %d distinct codes in 200 draws", len(seen))
	}
}
