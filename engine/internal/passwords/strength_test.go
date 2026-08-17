package passwords

import "testing"

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
