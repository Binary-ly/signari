package passwords

import (
	"math/rand/v2"
	"testing"
)

func TestEstimateRanksRealPasswords(t *testing.T) {
	for _, c := range []struct {
		pw       string
		maxScore int
		why      string
	}{
		{"Password123!", 2, "satisfies every composition rule, in every corpus"},
		{"aaaaaaaaaaaa", 1, "one character repeated"},
		{"qwertyuiop12", 2, "keyboard walk"},
		{"abcdefghijkl", 1, "a sequence"},
		{"19850312", 1, "a date"},
		{"p@ssw0rd", 2, "leetspeak is not strength"},
		{"abcabcabcabc", 1, "a repeated block"},
		{"123456789012", 1, "digits only"},
	} {
		s := Estimate(c.pw, "")
		if s.Score > c.maxScore {
			t.Errorf("%q scored %d (want <= %d) -- %s [%s]", c.pw, s.Score, c.maxScore, c.why, s)
		}
	}
	for _, pw := range []string{
		"seven-lamps-drift-inland",
		"quiet-harbour-nine-stones",
		"correct horse battery staple",
	} {
		s := Estimate(pw, "")
		if s.Score < 4 {
			t.Errorf("passphrase %q scored only %d [%s]", pw, s.Score, s)
		}
	}
}

// A pattern costs only the part of the password it covers; the rest is still
// charged at brute force. Scoring the whole password as the pattern refused
// about one random 32-character password in forty: three equal letters
// anywhere in it, once lowercased, priced all thirty-two characters at 832
// guesses, and the person was told their generated password was "built around"
// something a person would choose. Measured with this seed before the fix:
// 54 of 2,000 random 32-character base64url passwords fell under the default
// MinScore of 3, and 19 of 2,000 at 16 characters.
func TestAPatternInsideARandomPasswordCostsOnlyItsOwnPart(t *testing.T) {
	for _, pw := range []string{
		"Tz7#Lq2vmaaaR9!kW4pDx8", // a run
		"Tz7#Lq2vmabcdR9!kW4pDx", // a sequence
		"Tz7#Lq2vmqwerR9!kW4pDx", // a keyboard walk
		"Tz7#Lq2vm@4aR9!kW4pDx8", // a run once de-leeted
	} {
		if s := Estimate(pw, ""); s.Score < 4 {
			t.Errorf("%q scored %d [%s]: the pattern priced the whole password", pw, s.Score, s)
		}
	}

	// What a password manager generates must never be refused. Seeded, so a
	// failure names the same password every run.
	rng := rand.New(rand.NewPCG(4, 24))
	alphabets := []string{
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*",
		"abcdefghijklmnopqrstuvwxyz0123456789",
	}
	for _, a := range alphabets {
		for _, n := range []int{16, 20, 32} {
			for i := 0; i < 2000; i++ {
				b := make([]byte, n)
				for j := range b {
					b[j] = a[rng.IntN(len(a))]
				}
				if s := Estimate(string(b), ""); s.Score < 4 {
					t.Fatalf("a random %d-character password %q scored %d [%s]", n, b, s.Score, s)
				}
			}
		}
	}
}

func TestEstimateKnowsWhoYouAre(t *testing.T) {
	weak := Estimate("alice-t-lives-here", "alice-t@example.com")
	strong := Estimate("alice-t-lives-here", "")
	if weak.Score >= strong.Score {
		t.Fatalf("knowing the identity did not lower the score: %s vs %s", weak, strong)
	}
	if weak.Pattern == "" {
		t.Fatal("no pattern named")
	}
}
