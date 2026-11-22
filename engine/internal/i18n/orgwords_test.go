package i18n

import (
	"strings"
	"testing"
)

// An organisation's words are a tenant's rather than ours, so a catalogue
// message's trust does not extend to them: T may emit a catalogue message's markup
// and must escape theirs, whole, with the arguments still substituted and escaped.
func TestAnOrganisationsWordsCannotCarryMarkup(t *testing.T) {
	base := load(t, "").For("en")
	own := base.With(map[string]string{
		"consent.heading": `<img src=x onerror=alert(1)> {Client} & co`,
	})

	got := string(own.T("consent.heading", map[string]any{"Client": "<b>Wiki</b>"}))
	if strings.Contains(got, "<img") || strings.Contains(got, "<b>") {
		t.Fatalf("an organisation's words reached the page as markup: %s", got)
	}
	if !strings.Contains(got, "&lt;img") || !strings.Contains(got, "&lt;b&gt;Wiki") || !strings.Contains(got, "&amp; co") {
		t.Errorf("the words were not rendered as text: %s", got)
	}

	// In mail there is no markup to escape, and escaping would mangle it.
	if got := own.Text("consent.heading", map[string]any{"Client": "Wiki"}); got != `<img src=x onerror=alert(1)> Wiki & co` {
		t.Errorf("as text it reads %q", got)
	}

	// Anything else is the catalogue's, and the printer it came from is untouched.
	if got := string(own.T("login.heading")); got != "Sign in" {
		t.Errorf("an untouched message reads %q", got)
	}
	if !strings.Contains(string(base.T("consent.heading", map[string]any{"Client": "Wiki"})), "<strong>") {
		t.Error("rewording through one printer changed the catalogue's")
	}
	if base.With(nil) != base || base.Worded() || !own.Worded() {
		t.Error("a printer with no words should be the catalogue's own")
	}
}

// Each refusal is a message that would be stored, reported as saved, and either
// change nothing or print a hole.
func TestAMessageIsRewordedOnlyWhereItWouldRender(t *testing.T) {
	b := load(t, "")
	for name, c := range map[string]struct{ lang, key, text, says string }{
		"a key nobody renders":      {"en", "login.haeding", "Hi", "not a message"},
		"a language with none":      {"xx", "login.heading", "Hi", "no catalogue"},
		"a message that counts":     {"en", "common.minutes", "soon", "counts something"},
		"nothing":                   {"en", "login.heading", "", "1 to 2000"},
		"too much":                  {"en", "login.heading", strings.Repeat("a", 2001), "1 to 2000"},
		"a placeholder it is given": {"en", "login.heading", "Hi {Client}", "never given {Client}"},
	} {
		err := b.CheckWords(c.lang, c.key, c.text)
		if err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v, want it to say %q", name, err, c.says)
		}
	}
	for _, c := range []struct{ lang, key, text string }{
		{"en", "login.heading", "Welcome to Acme"},
		{"ar", "login.heading", "مرحبا"},
		{"en", "consent.title", "Let {Client} in"},
		{"en", "login.heading", strings.Repeat("م", 2000)},
	} {
		if err := b.CheckWords(c.lang, c.key, c.text); err != nil {
			t.Errorf("%s %q was refused: %v", c.key, c.text[:6], err)
		}
	}
	var none *Bundle
	if err := none.CheckWords("en", "login.heading", "Hi"); err == nil {
		t.Error("a catalogue that did not load accepted a message")
	}
}
