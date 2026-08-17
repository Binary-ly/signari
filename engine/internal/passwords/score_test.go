package passwords

import "testing"

// The score floor, measured rather than assumed.
//
// The default was first set to 2 and `Password123!` walked straight through it
// -- it scores exactly 2, as do `Summer2026!`, `admin123` and the four-character
// `gT4v`. That is what the table below exists to prevent recurring: a floor that
// admits the most-guessed password shape in the world is not a floor.
func TestTheDefaultFloorRefusesTheObviousAndAdmitsTheReasonable(t *testing.T) {
	const floor = 3 // must match PolicyFromEnv's default

	for _, pw := range []string{
		"Password123!", "password", "p@ssw0rd", "Summer2026!", "qwertyuiop12",
		"aaaaaaaaaaaa", "abcdefghijkl", "19850312", "admin123", "letmein1",
		"hunter2", "gT4v", "abcabcabcabc", "123456789012",
	} {
		if s := Estimate(pw, ""); s.Score >= floor {
			t.Errorf("%q scores %d and would be ACCEPTED at the default floor of %d [%s]",
				pw, s.Score, floor, s)
		}
	}

	// Refusing weak passwords is easy; the hard part is not refusing reasonable
	// ones. A policy people cannot satisfy is a policy people write on a note.
	for _, pw := range []string{
		"seven-lamps-drift-inland", "quiet-harbour-nine-stones",
		"correct horse battery staple", "thistlebrook", "xK7#mQ2$vL9",
	} {
		if s := Estimate(pw, ""); s.Score < floor {
			t.Errorf("%q scores only %d and would be REFUSED at the default floor "+
				"of %d [%s]", pw, s.Score, floor, s)
		}
	}
}

// Structure and history are different questions, and neither answers the other.
func TestStrengthAndTheCorpusCatchDifferentThings(t *testing.T) {
	// Famously in every breach corpus, and structurally unremarkable -- the
	// estimator rates it well and is right to. Only the corpus knows.
	if s := Estimate("Tr0ub4dor&3", ""); s.Score < 3 {
		t.Fatalf("Tr0ub4dor&3 scored %d; the estimator is guessing at history "+
			"rather than measuring structure", s.Score)
	}
	// Conversely, structurally cheap and possibly never leaked verbatim.
	if s := Estimate("qwertyuiopasdfgh", ""); s.Score >= 3 {
		t.Fatalf("a sixteen-character keyboard walk scored %d", s.Score)
	}
}
