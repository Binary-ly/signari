// Package brand carries an organisation's appearance onto the pages a user
// sees before and during sign-in.
//
// # Colours and a logo, never CSS
//
// The obvious way to build this is a text box holding custom CSS, and that is
// what the other products do. It is also a stored cross-site scripting vector
// aimed at the single worst page in the product: CSS can load fonts and images
// from anywhere, `url()` exfiltrates the page's own state through attribute
// selectors, and an administrator who can style the login page can restyle it
// into a convincing form that posts elsewhere.
//
// So a brand is a fixed set of TOKENS -- a product name, a logo URL, four
// colours -- each validated before it is stored and each emitted as a CSS
// custom property. There is no path from a brand to arbitrary markup or
// arbitrary style rules.
//
// # Contrast is checked, not trusted
//
// Roughly every self-hosted deployment that offers colour customisation ends up
// with at least one tenant whose login page is grey text on a white background,
// because the person choosing the colours was matching a brand guide on a
// different medium and never looked at the result on a phone in daylight.
//
// The contrast ratio is arithmetic. Checking it at the moment the colours are
// set costs nothing and removes a class of bug that is otherwise found by the
// people least able to report it.
package brand

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Brand is one organisation's appearance.
type Brand struct {
	// ProductName replaces "Signari" in page titles and headings.
	ProductName string
	// LogoURL is shown above the sign-in form. https only.
	LogoURL string
	// SupportURL is offered when somebody cannot get in. https only, and worth
	// setting: the alternative is a user with no route to a human.
	SupportURL string

	// Primary is the colour of buttons and links.
	Primary string
	// OnPrimary is the text ON those buttons.
	OnPrimary string
	// Background and Text are the page.
	Background string
	Text       string
}

// minContrast is WCAG 2.1 AA for body text.
//
// 4.5:1 rather than the 3:1 allowed for large text, because the things that
// matter on these pages -- field labels, error messages, the reason a sign-in
// was refused -- are body text, and an error nobody can read is an error that
// becomes a support call.
const minContrast = 4.5

var hexColour = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

// Validate refuses a brand that would produce an unusable or unsafe page.
//
// Every failure names the field and says what to do, because whoever sets a
// brand is usually not the person who wrote the brand guide and cannot act on
// "invalid colour".
func (b *Brand) Validate() error {
	if len(b.ProductName) > 60 {
		return fmt.Errorf("the product name is %d characters; 60 is the most that "+
			"fits a page heading without wrapping", len(b.ProductName))
	}
	for field, u := range map[string]string{"logo URL": b.LogoURL, "support URL": b.SupportURL} {
		if u == "" {
			continue
		}
		if !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("the %s must be https: %q would make every sign-in "+
				"page a mixed-content warning, and on the one page where users are "+
				"asked to judge whether a site is genuine", field, u)
		}
	}

	colours := []struct {
		name, value string
	}{
		{"primary", b.Primary}, {"on-primary", b.OnPrimary},
		{"background", b.Background}, {"text", b.Text},
	}
	set := 0
	for _, c := range colours {
		if c.value == "" {
			continue
		}
		set++
		if !hexColour.MatchString(c.value) {
			return fmt.Errorf("%s is %q; colours must be hex like #1a2b3c or #abc. "+
				"Names and rgb() are not accepted because the value is emitted into "+
				"a stylesheet", c.name, c.value)
		}
	}
	// Partly-set palettes are the ones that produce unreadable pages: a custom
	// background against the default text, or the reverse.
	if set != 0 && set != len(colours) {
		return fmt.Errorf("%d of %d colours are set. Set all four or none -- a "+
			"custom background against a default text colour is how a page ends up "+
			"unreadable", set, len(colours))
	}
	if set == 0 {
		return nil
	}

	for _, pair := range []struct{ a, b, what string }{
		{b.Text, b.Background, "text on the background"},
		{b.OnPrimary, b.Primary, "button text on the button"},
	} {
		r, err := Contrast(pair.a, pair.b)
		if err != nil {
			return err
		}
		if r < minContrast {
			// Two decimals, not one. A ratio of 4.478 displayed as "4.5" against a
			// threshold of "4.5" reads as a contradiction, and the first thing
			// somebody does with a contradictory error is disbelieve it.
			return fmt.Errorf("%s has a contrast ratio of %.2f:1, below the %.1f:1 "+
				"needed to be readable (WCAG 2.1 AA). %s against %s. Darken one or "+
				"lighten the other", pair.what, r, minContrast, pair.a, pair.b)
		}
	}
	return nil
}

// Contrast returns the WCAG 2.1 contrast ratio between two hex colours.
//
// The ratio is (lighter + 0.05) / (darker + 0.05) over relative luminance, and
// it runs from 1 (identical) to 21 (black on white).
func Contrast(a, b string) (float64, error) {
	la, err := luminance(a)
	if err != nil {
		return 0, err
	}
	lb, err := luminance(b)
	if err != nil {
		return 0, err
	}
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05), nil
}

// luminance is WCAG relative luminance.
//
// The per-channel curve is not a plain gamma: sRGB is linear near black and a
// 2.4 power above it, and using a single exponent instead gets dark colours
// wrong by enough to pass a palette that should fail.
func luminance(hex string) (float64, error) {
	if !hexColour.MatchString(hex) {
		return 0, fmt.Errorf("%q is not a hex colour", hex)
	}
	h := strings.TrimPrefix(hex, "#")
	if len(h) == 3 {
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	channel := func(i int) (float64, error) {
		v, err := strconv.ParseUint(h[i:i+2], 16, 8)
		if err != nil {
			return 0, err
		}
		c := float64(v) / 255
		if c <= 0.03928 {
			return c / 12.92, nil
		}
		return math.Pow((c+0.055)/1.055, 2.4), nil
	}
	r, err := channel(0)
	if err != nil {
		return 0, err
	}
	g, err := channel(2)
	if err != nil {
		return 0, err
	}
	bl, err := channel(4)
	if err != nil {
		return 0, err
	}
	return 0.2126*r + 0.7152*g + 0.0722*bl, nil
}

// CSS returns the custom properties for this brand, or "" if nothing is set.
//
// Safe to interpolate into a stylesheet: every value reaching here has been
// through Validate, so a colour is a hex literal and nothing else. The check is
// repeated rather than assumed, because this function is the one place where
// stored data becomes stylesheet text.
func (b *Brand) CSS() string {
	vals := [][2]string{
		{"--brand-primary", b.Primary},
		{"--brand-on-primary", b.OnPrimary},
		{"--brand-background", b.Background},
		{"--brand-text", b.Text},
	}
	var sb strings.Builder
	for _, v := range vals {
		if v[1] == "" || !hexColour.MatchString(v[1]) {
			continue
		}
		sb.WriteString(v[0])
		sb.WriteByte(':')
		sb.WriteString(v[1])
		sb.WriteByte(';')
	}
	if sb.Len() == 0 {
		return ""
	}
	return ":root{" + sb.String() + "}"
}
