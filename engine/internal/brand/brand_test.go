package brand

import (
	"math"
	"strings"
	"testing"
)

// TestContrastMatchesTheStandard pins the arithmetic against values published
// with WCAG 2.1, so a refactor of the luminance curve cannot quietly shift
// where the pass/fail line sits.
//
// The sRGB curve is linear below 0.03928 and a 2.4 power above it. Substituting
// a plain gamma is the usual simplification and it is wrong by enough on dark
// colours to let an unreadable palette through, which is precisely what this
// package exists to stop.
func TestContrastMatchesTheStandard(t *testing.T) {
	cases := []struct {
		a, b string
		want float64
	}{
		{"#000000", "#ffffff", 21},     // the maximum
		{"#ffffff", "#ffffff", 1},      // identical
		{"#777777", "#ffffff", 4.478},  // just under AA -- the interesting case
		{"#767676", "#ffffff", 4.541},  // just over
		{"#000000", "#7f7f7f", 5.245},  // mid grey on black
		{"#1a2b3c", "#ffffff", 14.436}, // a plausible brand navy
	}
	for _, c := range cases {
		got, err := Contrast(c.a, c.b)
		if err != nil {
			t.Fatalf("%s on %s: %v", c.a, c.b, err)
		}
		if math.Abs(got-c.want) > 0.01 {
			t.Errorf("contrast(%s, %s) = %.3f, want %.3f", c.a, c.b, got, c.want)
		}
	}
}

func TestContrastIsSymmetric(t *testing.T) {
	f, _ := Contrast("#123456", "#fedcba")
	r, _ := Contrast("#fedcba", "#123456")
	if math.Abs(f-r) > 1e-9 {
		t.Errorf("contrast is not symmetric: %.6f vs %.6f", f, r)
	}
}

func TestShorthandHexEqualsLonghand(t *testing.T) {
	a, err := Contrast("#abc", "#fff")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Contrast("#aabbcc", "#ffffff")
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(a-b) > 1e-9 {
		t.Errorf("#abc and #aabbcc disagree: %.6f vs %.6f", a, b)
	}
}

// TestAnUnreadablePaletteIsRefused is the whole point of the package.
func TestAnUnreadablePaletteIsRefused(t *testing.T) {
	b := &Brand{
		Primary: "#cccccc", OnPrimary: "#dddddd", // 1.2:1
		Background: "#ffffff", Text: "#000000",
	}
	err := b.Validate()
	if err == nil {
		t.Fatal("a palette with grey-on-grey button text was accepted")
	}
	if !strings.Contains(err.Error(), "contrast") {
		t.Errorf("the error does not mention contrast, so nobody will know what "+
			"to change: %v", err)
	}
}

func TestAReadablePaletteIsAccepted(t *testing.T) {
	b := &Brand{
		ProductName: "Acme Identity",
		LogoURL:     "https://acme.test/logo.svg",
		Primary:     "#0b5fff", OnPrimary: "#ffffff",
		Background: "#ffffff", Text: "#18181b",
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("a readable palette was refused: %v", err)
	}
}

// TestPartialPalettesAreRefused covers the failure this is most likely to see
// in practice: somebody sets a dark background and leaves the text default.
func TestPartialPalettesAreRefused(t *testing.T) {
	b := &Brand{Background: "#111111"}
	err := b.Validate()
	if err == nil {
		t.Fatal("a background with no text colour was accepted")
	}
	if !strings.Contains(err.Error(), "all four or none") {
		t.Errorf("the error should say to set all four or none: %v", err)
	}
}

// TestOnlyHexIsAccepted keeps the value safe to put in a stylesheet.
func TestOnlyHexIsAccepted(t *testing.T) {
	for _, bad := range []string{
		"red",
		"rgb(1,2,3)",
		"#12345",
		"#1a2b3c;} body{display:none",
		"var(--x)",
		"url(https://evil.test/x)",
	} {
		b := &Brand{Primary: bad, OnPrimary: "#fff", Background: "#fff", Text: "#000"}
		if err := b.Validate(); err == nil {
			t.Errorf("%q was accepted as a colour", bad)
		}
	}
}

// TestCSSCannotEscapeItsDeclaration is the injection check.
//
// CSS() is the one place stored data becomes stylesheet text. Even though
// Validate should have refused anything unsafe, this asserts the second gate
// holds on its own -- a brand written directly to the database by a migration
// or a repair script never passed through Validate at all.
func TestCSSCannotEscapeItsDeclaration(t *testing.T) {
	b := &Brand{
		Primary:    "#1a2b3c;} body{display:none",
		OnPrimary:  "#ffffff",
		Background: "expression(alert(1))",
		Text:       "#000000",
	}
	css := b.CSS()
	for _, forbidden := range []string{"expression", "display:none", "alert", "url("} {
		if strings.Contains(css, forbidden) {
			t.Errorf("CSS() emitted %q, which escapes the declaration: %s", forbidden, css)
		}
	}
	// Exactly one block. A second "{" or a third "}" would mean a value closed
	// the rule and opened another, which is the actual escape being tested for --
	// the closing brace of :root{...} is legitimate and must not be counted.
	if strings.Count(css, "{") != 1 || strings.Count(css, "}") != 1 {
		t.Errorf("CSS() produced more than one rule, so a value escaped: %s", css)
	}
	// The valid ones must still be there; refusing everything would pass this
	// test while breaking the feature.
	if !strings.Contains(css, "--brand-on-primary:#ffffff") {
		t.Errorf("a valid colour was dropped: %s", css)
	}
}

func TestNoColoursMeansNoStylesheet(t *testing.T) {
	b := &Brand{ProductName: "Acme"}
	if css := b.CSS(); css != "" {
		t.Errorf("a brand with no colours produced %q; it should produce nothing "+
			"so the default stylesheet is untouched", css)
	}
}

func TestInsecureURLsAreRefused(t *testing.T) {
	for _, u := range []string{"http://acme.test/logo.png", "javascript:alert(1)", "//acme.test/x"} {
		b := &Brand{LogoURL: u}
		if err := b.Validate(); err == nil {
			t.Errorf("%q was accepted as a logo URL", u)
		}
	}
}
