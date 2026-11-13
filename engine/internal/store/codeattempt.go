package store

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
)

// A sign-in code is bound to the sign-in that asked for it (ASVS 5.0.0 V6.6.2,
// specs/asvs-5.0.0.txt:2528-2530: "bound to the original authentication request
// for which they were generated and are not usable for a previous or subsequent
// one"). The attempt is an id the sign-in's own state carries: the pending
// token's for the code step, the reset link's for recovery. What is kept beside
// the code is its hash, so the table holds nothing that names a sign-in.
//
// A code was bound only to the person before. One sent for a sign-in in one
// browser finished another, and an LDAP bind or a desktop sign-in, which send no
// code, took one sent for something else. Neither has an attempt, so neither
// takes an emailed or texted code now.

// ErrNoAttempt is a sign-in code asked for without the sign-in it is for.
var ErrNoAttempt = errors.New("a sign-in code needs the sign-in it is for")

func attemptHash(attempt []byte) []byte {
	if len(attempt) == 0 {
		return nil
	}
	sum := sha256.Sum256(attempt)
	return sum[:]
}

// sameAttempt reports whether the code kept for held was issued to attempt.
// No attempt matches nothing, a held one included.
func sameAttempt(held, attempt []byte) bool {
	want := attemptHash(attempt)
	return held != nil && want != nil && subtle.ConstantTimeCompare(held, want) == 1
}
