package oauth

import "testing"

func TestAnErrorDescriptionStaysInTheRFCsCharacters(t *testing.T) {
	for in, want := range map[string]string{
		`plain words, and punctuation: ok!`: `plain words, and punctuation: ok!`,
		`scope "write" is not granted`:      `scope 'write' is not granted`,
		`C:\temp`:                           `C:/temp`,
		"two\nlines\ttabbed":                "two lines tabbed",
		"caf\u00e9":                         "caf ",
		"\x7f":                              " ",
	} {
		got := ErrorText(in)
		if got != want {
			t.Errorf("%q came out %q, want %q", in, got, want)
		}
		// RFC 6749 §5.2, the set itself: %x20-21 / %x23-5B / %x5D-7E.
		for _, c := range []byte(got) {
			if !(c >= 0x20 && c <= 0x21 || c >= 0x23 && c <= 0x5b || c >= 0x5d && c <= 0x7e) {
				t.Errorf("%q still holds %#x", got, c)
			}
		}
	}
}
