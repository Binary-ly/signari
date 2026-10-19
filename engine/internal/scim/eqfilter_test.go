package scim

import "testing"

// The one supported filter takes exactly one JSON string as its value (RFC
// 7644 Figure 1's compValue). A trailing expression was folded into the value,
// so `userName eq "a" or userName eq "b"` matched nobody instead of being
// refused (2.42).
func TestTheEqFilterTakesExactlyOneQuotedString(t *testing.T) {
	for in, want := range map[string]string{
		`userName eq "bjensen"`:    "bjensen",
		`USERNAME EQ "bjensen"`:    "bjensen",
		`userName eq "say \"hi\""`: `say "hi"`,
		`userName eq  "spaced"  `:  "spaced",
		`userName eq "a@b.x"`:      "a@b.x",
		``:                         "",
	} {
		got, err := ParseUserNameFilter(in)
		if err != nil || got != want {
			t.Errorf("%q gave %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		`userName eq "a" or userName eq "b"`,
		`userName eq "a" and active eq true`,
		`userName eq bjensen`,
		`userName eq ""`,
		`userName eq "unterminated`,
		`userName co "a"`,
		`emails eq "a@b.test"`,
	} {
		if got, err := ParseUserNameFilter(in); err == nil {
			t.Errorf("%q was accepted as %q", in, got)
		}
	}
	if got, err := ParseDisplayNameFilter(`displayName eq "A" or displayName eq "B"`); err == nil {
		t.Errorf("a group filter with a trailing expression was accepted as %q", got)
	}
}
