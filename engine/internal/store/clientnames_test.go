package store

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The marks that reverse the text around them, made from their code points so that no
// such character is in this file: a source file holding one reads differently in an
// editor from what the compiler sees.
var (
	rightToLeftOverride = string(rune(0x202e))
	leftToRightIsolate  = string(rune(0x2066))
	popDirectionalIsol  = string(rune(0x2069))
)

// A client's names in other languages are checked before they are stored (10.12): tags
// BCP 47 and one per tag whatever its case, names cleaned and not empty, and a bound.
func TestClientNamesAreCheckedBeforeTheyAreStored(t *testing.T) {
	got, err := NormaliseClientNames(map[string]string{"ja-Jpan-JP": "  クライアント名 ", "en-us": "My Client"})
	if err != nil {
		t.Fatal(err)
	}
	if got["ja-Jpan-JP"] != "クライアント名" || got["en-us"] != "My Client" || len(got) != 2 {
		t.Errorf("normalised to %v: tags kept as written, names trimmed", got)
	}

	many := map[string]string{}
	for i := 0; i <= MaxClientNames; i++ {
		many[fmt.Sprintf("x-n%d", i)] = "name"
	}
	for _, c := range []struct {
		name  string
		names map[string]string
		want  string
	}{
		{"a tag that is not one", map[string]string{"not a tag": "x"}, "not a BCP 47"},
		{"a tag with an empty subtag", map[string]string{"en--US": "x"}, "not a BCP 47"},
		{"two spellings of one tag", map[string]string{"en-US": "a", "en-us": "b"}, "same tag"},
		{"a name that is nothing once cleaned", map[string]string{"de": " " + rightToLeftOverride + "\x01 "}, "empty"},
		{"too many", many, "at most"},
	} {
		if _, err := NormaliseClientNames(c.names); !errors.Is(err, ErrInvalidClientName) ||
			!strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a refusal naming %q", c.name, err, c.want)
		}
	}
}

// The marks that reverse the text around them are taken out, so a name cannot make a
// consent screen read as something it does not say.
func TestAClientNameCannotReorderThePage(t *testing.T) {
	for in, want := range map[string]string{
		"Pay" + rightToLeftOverride + "LAPYAP":                    "PayLAPYAP",
		"a" + leftToRightIsolate + "b" + popDirectionalIsol + "c": "abc",
		"tab\tand\x00null":      "tabandnull",
		strings.Repeat("n", 70): strings.Repeat("n", 60),
	} {
		if got := CleanClientName(in); got != want {
			t.Errorf("%q cleaned to %q, want %q", in, got, want)
		}
	}
}
