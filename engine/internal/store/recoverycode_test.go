package store

import (
	"math"
	"strings"
	"testing"
)

// Recovery codes must be drawn uniformly, and must say honestly how strong they
// are.
//
// The comment on newRecoveryCode used to read "128 bits, in two readable
// groups". Both halves were wrong -- 20 characters of a 31-symbol alphabet is
// 99.1 bits, and the separator lands every five characters, so there are four
// groups. A number in a comment is what somebody quotes in a risk assessment.
//
// The draw was also biased. `alphabet[byte % 31]` over a uniform byte folds 256
// values onto 31 symbols, and 256 = 8*31 + 8, so the first EIGHT symbols came up
// on nine of the 256 byte values while the other twenty-three came up on eight.
// That is 12.5% more often for A-H.

// The shape the code claims.
func TestARecoveryCodeHasTheShapeTheCommentDescribes(t *testing.T) {
	c, err := newRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	groups := strings.Split(c, "-")
	if len(groups) != 4 {
		t.Errorf("got %d groups (%q), want 4 — the comment and the separator "+
			"interval disagree again", len(groups), c)
	}
	for _, g := range groups {
		if len(g) != 5 {
			t.Errorf("group %q is %d characters, want 5", g, len(g))
		}
	}
	body := strings.ReplaceAll(c, "-", "")
	if len(body) != 20 {
		t.Errorf("%d characters, want 20; the entropy claim of 99.1 bits assumes 20", len(body))
	}
	for _, r := range body {
		if !strings.ContainsRune(recoveryAlphabet, r) {
			t.Errorf("%q is outside the alphabet", r)
		}
	}
}

// The claimed entropy must match the alphabet actually in use.
func TestTheStatedEntropyMatchesTheAlphabet(t *testing.T) {
	bits := 20 * math.Log2(float64(len(recoveryAlphabet)))
	if math.Abs(bits-99.1) > 0.5 {
		t.Errorf("20 characters of a %d-symbol alphabet is %.1f bits, but the "+
			"comment on newRecoveryCode says 99.1. Change one of them",
			len(recoveryAlphabet), bits)
	}
}

// The bias test, aimed at the exact signature the bug produces.
//
// A max-deviation-across-all-symbols test would flake: with 31 buckets the
// largest of them naturally sits a couple of percent off. The modulo bias has a
// specific shape instead -- the symbols below `256 mod 31` are favoured and the
// rest are not -- so comparing those two groups isolates a 12.5% signal from
// noise that is an order of magnitude smaller.
func TestRecoveryCodesAreDrawnWithoutModuloBias(t *testing.T) {
	remainder := 256 % len(recoveryAlphabet)
	if remainder == 0 {
		t.Skip("the alphabet divides 256, so folding could not bias anything")
	}

	counts := map[rune]int{}
	const draws = 20000
	for i := 0; i < draws; i++ {
		c, err := newRecoveryCode()
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range strings.ReplaceAll(c, "-", "") {
			counts[r]++
		}
	}

	var favoured, rest float64
	for i, r := range recoveryAlphabet {
		if i < remainder {
			favoured += float64(counts[r])
		} else {
			rest += float64(counts[r])
		}
	}
	favouredMean := favoured / float64(remainder)
	restMean := rest / float64(len(recoveryAlphabet)-remainder)

	// Folding makes the first `remainder` symbols appear (8+1)/8 as often.
	excess := (favouredMean/restMean - 1) * 100
	t.Logf("first %d symbols vs the rest: %+.2f%% (folding would give about +12.5%%)",
		remainder, excess)

	if excess > 5 {
		t.Errorf("the first %d symbols of the alphabet come up %.2f%% more often "+
			"than the rest. That is modulo bias: a uniform byte folded onto %d "+
			"symbols favours the first %d. Draw with rejection instead",
			remainder, excess, len(recoveryAlphabet), remainder)
	}
}
