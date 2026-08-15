package oauth

import (
	"strings"
	"testing"
)

// TestUserCodeAlphabetExcludesConfusables.
//
// The whole point of the alphabet: a code read off a television across a room
// and typed on a phone must not contain characters people reliably misread.
func TestUserCodeAlphabetExcludesConfusables(t *testing.T) {
	for _, r := range "BIOSZ0123456789" {
		if strings.ContainsRune(DeviceCodeAlphabet, r) {
			t.Errorf("the alphabet contains %q, which is routinely misread", r)
		}
	}
	seen := map[rune]bool{}
	for _, r := range DeviceCodeAlphabet {
		if seen[r] {
			t.Errorf("the alphabet repeats %q, which skews the distribution", r)
		}
		seen[r] = true
	}
	if len(DeviceCodeAlphabet) != 21 {
		t.Errorf("alphabet is %d characters; the entropy claim in the comment "+
			"assumes 21", len(DeviceCodeAlphabet))
	}
}

func TestNewUserCodeShape(t *testing.T) {
	for i := 0; i < 200; i++ {
		c, err := NewUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != UserCodeLength {
			t.Fatalf("code %q is %d characters, want %d", c, len(c), UserCodeLength)
		}
		if !ValidUserCodeShape(c) {
			t.Fatalf("a generated code failed its own shape check: %q", c)
		}
	}
}

func TestUserCodesDiffer(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		c, err := NewUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if seen[c] {
			t.Fatalf("a code repeated within 500 draws: %q", c)
		}
		seen[c] = true
	}
}

// TestNormalizeRoundTripsFormattedCodes. What a person is shown is what they
// type back, hyphen and all.
func TestNormalizeRoundTripsFormattedCodes(t *testing.T) {
	for i := 0; i < 50; i++ {
		c, err := NewUserCode()
		if err != nil {
			t.Fatal(err)
		}
		shown := FormatUserCode(c)
		if got := NormalizeUserCode(shown); got != c {
			t.Fatalf("displaying %q as %q and typing it back gave %q", c, shown, got)
		}
		// And the ways people actually type: lowercase, spaces, no separator.
		for _, variant := range []string{
			strings.ToLower(shown),
			strings.ReplaceAll(shown, "-", " "),
			strings.ReplaceAll(shown, "-", ""),
			"  " + shown + "  ",
			strings.ReplaceAll(shown, "-", "_"),
		} {
			if got := NormalizeUserCode(variant); got != c {
				t.Errorf("typing %q gave %q, want %q", variant, got, c)
			}
		}
	}
}

// TestNormalizeDoesNotRewriteAlphabetCharacters.
//
// A draft of this mapped "confusable" characters to what the reader supposedly
// meant. It rewrote L, which IS in the alphabet, and mapped Z to a character
// that is not -- silently corrupting correct codes into ones that could never
// match. The rule now: normalisation removes separators and changes case, and
// touches nothing else.
func TestNormalizeDoesNotRewriteAlphabetCharacters(t *testing.T) {
	for _, r := range DeviceCodeAlphabet {
		in := strings.Repeat(string(r), UserCodeLength)
		if got := NormalizeUserCode(in); got != in {
			t.Errorf("normalising %q changed it to %q; every alphabet character "+
				"must survive untouched", in, got)
		}
	}
}

// TestShapeCheckRejectsExcludedCharacters. A code containing one of these is a
// misreading that cannot match any record, so it is refused before it reaches a
// query rather than counted as an attempt.
func TestShapeCheckRejectsExcludedCharacters(t *testing.T) {
	for _, bad := range []string{
		"ACDEFGHB", // B excluded
		"ACDEFGHI", // I
		"ACDEFGHO", // O
		"ACDEFGHS", // S
		"ACDEFGHZ", // Z
		"ACDEFGH0", // digit
		"ACDEFGH",  // too short
		"ACDEFGHJK",
		"",
		"acdefghj", // lowercase reaches here only if normalisation was skipped
	} {
		if ValidUserCodeShape(bad) {
			t.Errorf("%q was accepted as a possible user code", bad)
		}
	}
}

func TestFormatUserCode(t *testing.T) {
	if got := FormatUserCode("ACDEFGHJ"); got != "ACDE-FGHJ" {
		t.Errorf("FormatUserCode = %q, want ACDE-FGHJ", got)
	}
	// Anything that is not a full code is returned untouched rather than
	// mangled into a shape that looks official.
	if got := FormatUserCode("SHORT"); got != "SHORT" {
		t.Errorf("FormatUserCode(%q) = %q, want it unchanged", "SHORT", got)
	}
}

func TestDeviceCodeGrantIsAccepted(t *testing.T) {
	if err := ValidateGrantType(GrantTypeDeviceCode); err != nil {
		t.Fatalf("the device code grant was rejected: %v", err)
	}
}
