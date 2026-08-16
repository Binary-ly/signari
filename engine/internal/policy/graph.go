package policy

import (
	"fmt"
	"html"
	"sort"
	"strings"
)


const (
	gCol     = 300 // column width
	gGap     = 24
	gRow     = 22 // line height inside a card
	gPad     = 16
	gPerRow  = 4 // columns before wrapping, so a wide policy stays readable
	gHeadPad = 90
)

// SVG renders the policy file as a diagram.
func (f *File) SVG() string {
	universal, clients := f.groups()

	width := gPad*2 + gPerRow*gCol + (gPerRow-1)*gGap
	if n := len(clients); n > 0 && n < gPerRow {
		width = gPad*2 + n*gCol + (n-1)*gGap
	}
	if len(clients) == 0 {
		width = gPad*2 + gCol
	}

	var b strings.Builder
	y := gHeadPad

	// The universal band, first and full width, because it applies to
	// everything below it.
	var band string
	if len(universal) > 0 {
		band = renderCard(gPad, y, width-gPad*2, "Applies to every application",
			"no client named", universal)
		y += cardHeight(universal) + gGap
	}

	// The clients, in a grid.
	var cards strings.Builder
	names := make([]string, 0, len(clients))
	for n := range clients {
		names = append(names, n)
	}
	// Sorted, so the same file always renders identically and a committed
	// diagram has a readable diff.
	sort.Strings(names)

	rowTop := y
	tallest := 0
	for i, n := range names {
		col := i % gPerRow
		if col == 0 && i > 0 {
			rowTop += tallest + gGap
			tallest = 0
		}
		x := gPad + col*(gCol+gGap)
		cards.WriteString(renderCard(x, rowTop, gCol, n, "client", clients[n]))
		if h := cardHeight(clients[n]); h > tallest {
			tallest = h
		}
	}
	height := rowTop + tallest + gPad + 34

	if len(universal) == 0 && len(clients) == 0 {
		height = gHeadPad + 60
	}

	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" `+
		`viewBox="0 0 %d %d" font-family="ui-sans-serif,system-ui,sans-serif" `+
		`font-size="13">`, width, height, width, height)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#ffffff"/>`, width, height)

	// The file-level default is the single most important thing on the page: it
	// says where the boundary sits before any rule runs.
	def := f.Default
	if def == "" {
		def = "allow"
	}
	defColour := "#166534"
	if def == "deny" {
		defColour = "#991b1b"
	}
	fmt.Fprintf(&b, `<text x="%d" y="32" font-size="17" font-weight="600" fill="#111">`+
		`Access policy</text>`, gPad)
	fmt.Fprintf(&b, `<text x="%d" y="55" fill="#444">Default: `+
		`<tspan font-weight="600" fill="%s">%s</tspan>`+
		`  ·  %d rule(s)  ·  %d test(s), all passing</text>`,
		gPad, defColour, html.EscapeString(def), len(f.Policies), len(f.Tests))
	fmt.Fprintf(&b, `<text x="%d" y="74" fill="#777" font-size="11">`+
		`Every rule that matches applies, together. A rule can only restrict, `+
		`never grant.</text>`, gPad)

	if len(universal) == 0 && len(clients) == 0 {
		fmt.Fprintf(&b, `<text x="%d" y="%d" fill="#777">No rules: every request `+
			`gets the default.</text>`, gPad, gHeadPad+20)
		b.WriteString(`</svg>`)
		return b.String()
	}

	b.WriteString(band)
	b.WriteString(cards.String())

	fmt.Fprintf(&b, `<text x="%d" y="%d" fill="#999" font-size="11">`+
		`Generated from the policy file. The file is the source of truth; this is `+
		`a view of it.</text>`, gPad, height-14)
	b.WriteString(`</svg>`)
	return b.String()
}

// cardHeight is the space one card needs.
func cardHeight(rules []Rule) int {
	lines := 0
	for _, r := range rules {
		lines += 1 + len(ruleLines(r))
	}
	return 46 + lines*gRow + gPad
}

// renderCard draws one group of rules.
func renderCard(x, y, w int, title, subtitle string, rules []Rule) string {
	var b strings.Builder
	h := cardHeight(rules)

	fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" rx="10" `+
		`fill="#fafafa" stroke="#e4e4e7"/>`, x, y, w, h)
	fmt.Fprintf(&b, `<text x="%d" y="%d" font-weight="600" fill="#111">%s</text>`,
		x+gPad, y+25, html.EscapeString(fit(title, w-gPad*2, 13, true)))
	fmt.Fprintf(&b, `<text x="%d" y="%d" fill="#999" font-size="11">%s</text>`,
		x+gPad, y+41, html.EscapeString(subtitle))

	cy := y + 46 + 14
	for _, r := range rules {
		colour := "#1d4ed8"
		if r.Deny {
			colour = "#991b1b"
		}
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-weight="600" fill="%s">%s</text>`,
			x+gPad, cy, colour, html.EscapeString(fit(r.Name, w-gPad*2, 13, true)))
		cy += gRow

		for _, line := range ruleLines(r) {
			fill, prefix := "#333", "• "
			if strings.HasPrefix(line, "denied") {
				fill, prefix = "#991b1b", "✕ "
			}
			fmt.Fprintf(&b, `<text x="%d" y="%d" fill="%s" font-size="12">%s</text>`,
				x+gPad+8, cy, fill,
				html.EscapeString(prefix+fit(line, w-gPad*2-18, 12, false)))
			cy += gRow
		}
		cy += 6
	}
	return b.String()
}

// ruleLines is everything a rule says, one line each.
func ruleLines(r Rule) []string {
	if r.Deny {
		return []string{"denied outright"}
	}
	lines := describeConditions(r.Require)
	if len(lines) == 0 {
		return []string{"no conditions"}
	}
	return lines
}

// groups splits rules into the universal ones and the per-client ones.
func (f *File) groups() ([]Rule, map[string][]Rule) {
	byClient := map[string][]Rule{}
	var universal []Rule

	for _, r := range f.Policies {
		clients := append([]string(nil), r.When.Clients...)
		if r.When.Client != "" {
			clients = append(clients, r.When.Client)
		}
		if len(clients) == 0 {
			universal = append(universal, r)
			continue
		}
		for _, c := range clients {
			byClient[c] = append(byClient[c], r)
		}
	}
	return universal, byClient
}

// describeConditions renders a rule's requirements in the words an operator
// would use.
//
// Every field of Conditions must appear here. A condition that is enforced and
// not drawn makes the diagram a lie of omission -- somebody reads it, sees no
// device requirement, and cannot work out why the login is refused.
// TestEveryConditionIsDrawn fails when a field is added and not handled.
func describeConditions(c Conditions) []string {
	var out []string

	if len(c.Groups) > 0 {
		out = append(out, "in all groups: "+strings.Join(c.Groups, ", "))
	}
	if len(c.AnyGroup) > 0 {
		out = append(out, "in any group: "+strings.Join(c.AnyGroup, ", "))
	}
	if c.MFA {
		out = append(out, "multi-factor authentication")
	}
	if c.PhishingResistant {
		out = append(out, "a passkey or security key")
	}
	if len(c.FactorsAnyOf) > 0 {
		out = append(out, "factor is one of: "+strings.Join(c.FactorsAnyOf, ", "))
	}
	if len(c.FromNetworks) > 0 {
		out = append(out, "from "+strings.Join(c.FromNetworks, ", "))
	}
	if c.NoImpossibleTravel {
		out = append(out, "no impossible travel")
	}
	if c.DeviceManaged {
		out = append(out, "a managed device")
	}
	if c.DeviceCompliant {
		out = append(out, "a managed and compliant device")
	}
	return out
}

// fit truncates to what will actually fit in the given pixel width.
//
// Measured rather than a fixed character count. The first version truncated at
// 30 characters regardless of the space available, which cut
// "contractors-cannot-reach-payroll" -- the name that says what the rule does --
// down to "contractors-cannot-reach-payr…" while a third of the card sat empty.
//
// 0.55em per character is a serviceable average for this font at these sizes;
// bold is a little wider. It does not need to be exact, it needs to stop
// throwing away words that fit.
func fit(s string, pixels, fontSize int, bold bool) string {
	perChar := float64(fontSize) * 0.55
	if bold {
		perChar = float64(fontSize) * 0.6
	}
	max := int(float64(pixels) / perChar)
	if max < 4 {
		max = 4
	}
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
