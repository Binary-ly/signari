package oauth

import (
	"errors"
	"strings"
	"testing"
)

// The RFC 7636 appendix B worked example. Anchoring to the spec's own vector
// catches an encoding mistake that a self-consistent round-trip test would miss:
// if Challenge() and VerifyPKCE() are wrong in the same way, they still agree.
func TestChallengeMatchesRFC7636Vector(t *testing.T) {
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	if got := Challenge(verifier); got != challenge {
		t.Fatalf("Challenge() = %q, want the RFC 7636 value %q", got, challenge)
	}
	if err := VerifyPKCE("S256", challenge, verifier); err != nil {
		t.Fatalf("the spec's own vector failed to verify: %v", err)
	}
}

func TestVerifyPKCERejects(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := Challenge(verifier)

	tests := []struct {
		name      string
		method    string
		challenge string
		verifier  string
		want      error
	}{
		{
			name:   "plain method is refused, not compared directly",
			method: "plain", challenge: verifier, verifier: verifier,
			want: ErrPKCEMismatch,
		},
		{
			name:   "empty method",
			method: "", challenge: challenge, verifier: verifier,
			want: ErrPKCEMismatch,
		},
		{
			name:   "wrong verifier",
			method: "S256", challenge: challenge,
			verifier: "0000000000000000000000000000000000000000000",
			want:     ErrPKCEMismatch,
		},
		{
			name:   "verifier too short",
			method: "S256", challenge: challenge, verifier: strings.Repeat("a", 42),
			want: ErrPKCEMalformed,
		},
		{
			name:   "verifier too long",
			method: "S256", challenge: challenge, verifier: strings.Repeat("a", 129),
			want: ErrPKCEMalformed,
		},
		{
			name:   "verifier with characters outside the unreserved set",
			method: "S256", challenge: challenge, verifier: strings.Repeat("a", 40) + "+/=",
			want: ErrPKCEMalformed,
		},
		{
			name:   "empty verifier",
			method: "S256", challenge: challenge, verifier: "",
			want: ErrPKCEMalformed,
		},
		{
			// The stored challenge being empty must never mean "anything matches".
			name:   "empty stored challenge",
			method: "S256", challenge: "", verifier: verifier,
			want: ErrPKCEMismatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyPKCE(tc.method, tc.challenge, tc.verifier)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// Verifiers at both ends of the legal range must be accepted; the bounds are
// inclusive in the RFC and an off-by-one here rejects valid clients.
func TestVerifierBoundsAreInclusive(t *testing.T) {
	for _, n := range []int{43, 128} {
		v := strings.Repeat("a", n)
		if err := VerifyPKCE("S256", Challenge(v), v); err != nil {
			t.Errorf("a %d-character verifier was rejected: %v", n, err)
		}
	}
}
