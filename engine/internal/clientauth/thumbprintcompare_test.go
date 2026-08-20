package clientauth

import (
	"bytes"
	"testing"
)

// constantTimeEqualBytes compares certificate thumbprints, which is to say it
// decides whether a TLS client is the one a token was bound to. The length check
// is the part that survived mutation against the whole suite.
//
// Without it the loop runs `for i := range a`, so:
//
//   - a SHORTER b panics on the first out-of-range index; and
//   - a LONGER b compares only the first len(a) bytes and returns true, which
//     makes a prefix a match.
//
// Both thumbprints are SHA-256 today, so the lengths always agree and neither
// case can be reached from the current call sites. That is exactly why it needs
// a test: the guard's whole job is to be correct for inputs the callers do not
// currently produce, and nothing else in the suite would notice it leaving.
func TestThumbprintComparisonIsNotSatisfiedByAPrefix(t *testing.T) {
	full := bytes.Repeat([]byte{0xAB}, 32)

	if !constantTimeEqualBytes(full, bytes.Repeat([]byte{0xAB}, 32)) {
		t.Fatal("two identical thumbprints did not compare equal")
	}

	// A prefix of a valid thumbprint must not authenticate.
	for _, n := range []int{0, 1, 16, 31} {
		if constantTimeEqualBytes(full[:n], full) {
			t.Errorf("a %d-byte prefix matched a 32-byte thumbprint; a client "+
				"presenting a truncated thumbprint would authenticate as the "+
				"holder of the full one", n)
		}
		// And the other way round, which is the panicking direction.
		if constantTimeEqualBytes(full, full[:n]) {
			t.Errorf("a 32-byte thumbprint matched its own %d-byte prefix", n)
		}
	}

	// Same length, one byte different, at each end and the middle.
	for _, i := range []int{0, 15, 31} {
		other := bytes.Repeat([]byte{0xAB}, 32)
		other[i] ^= 0xFF
		if constantTimeEqualBytes(full, other) {
			t.Errorf("thumbprints differing at byte %d compared equal", i)
		}
	}
}
