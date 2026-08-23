package i18n

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/text/language"
)

func load(t *testing.T, dir string) *Bundle {
	t.Helper()
	b, problems, err := Load(dir)
	if err != nil {
		t.Fatalf("loading catalogues: %v", err)
	}
	if len(problems) > 0 {
		t.Fatalf("unexpected refusals: %v", problems)
	}
	return b
}

// The defect this package exists for.
//
// The front-channel logout page said "{{len .Targets}} application(s)", which
// is wrong in English at one and unrepresentable in any language with more than
// two forms. Nothing caught it because the page rendered.
func TestAMessageThatCountsUsesTheRightFormPerLanguage(t *testing.T) {
	b := load(t, "")

	cases := []struct {
		lang string
		n    int
		want string
	}{
		{"en", 1, "1 application."},
		{"en", 3, "3 applications."},
		{"en", 0, "0 applications."},
	}
	for _, tc := range cases {
		// Isolates stripped: this is a test about which plural form was
		// chosen, and the directional marks around the number are a separate
		// property with its own test.
		got := visible(string(b.For(tc.lang).N("fclogout.progress", tc.n)))
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s n=%d: got %q, which does not contain %q",
				tc.lang, tc.n, got, tc.want)
		}
	}
}

// visible drops the bidirectional isolates, leaving what a reader sees.
func visible(s string) string {
	return strings.NewReplacer(firstStrongIsolate, "", popDirectional, "").Replace(s)
}

// CLDR, not `if n == 1`.
//
// Russian puts 21 in the same form as 1 and 5 in another; French puts 0 with 1.
// Any hand-rolled rule gets at least one of these wrong, and gets it wrong
// invisibly. This asserts the FORM chosen, independently of any translation
// existing, which is what makes it a test of the machinery rather than of the
// catalogue.
func TestPluralFormSelectionFollowsCLDRRatherThanEnglishIntuition(t *testing.T) {
	b := load(t, "")

	cases := []struct {
		lang string
		n    int
		form string
	}{
		{"en", 1, "one"}, {"en", 2, "other"},
		{"ru", 1, "one"}, {"ru", 21, "one"}, {"ru", 2, "few"}, {"ru", 5, "many"},
		{"fr", 0, "one"}, {"fr", 1, "one"}, {"fr", 2, "other"},
		{"ar", 0, "zero"}, {"ar", 1, "one"}, {"ar", 2, "two"},
		{"ar", 3, "few"}, {"ar", 11, "many"}, {"ar", 100, "other"},
		{"ja", 1, "other"},
	}
	for _, tc := range cases {
		// For() falls back to English for a language with no catalogue, so the
		// tag is taken directly: the rule is a property of the language, not of
		// whether somebody has translated anything into it yet.
		p := &Printer{b: b, lang: tc.lang, tag: language.Make(tc.lang)}
		got := formName[cardinalForm(p, tc.n)]
		if got != tc.form {
			t.Errorf("%s n=%d: CLDR says %q, this package chose %q",
				tc.lang, tc.n, tc.form, got)
		}
	}
}

// The safety property the whole design rests on.
//
// A message is ours and may contain markup, so T returns template.HTML and is
// NOT escaped again by the template engine. Everything substituted in is data
// -- an email address, a client name, a phone number, any of which can come
// from a stranger -- and must be escaped here, because the surrounding
// template will not do it a second time.
func TestAnArgumentCannotInjectMarkup(t *testing.T) {
	b := load(t, "")

	got := string(b.For("en").T("smsotp.sent", map[string]any{
		"Number": `<script>alert(1)</script>`,
	}))

	if strings.Contains(got, "<script>") {
		t.Fatalf("an argument reached the page as live markup: %s", got)
	}
	if !strings.Contains(got, "&lt;script&gt;") {
		t.Errorf("the argument should be escaped, got %q", got)
	}
	// The message's OWN markup must survive, or the split is pointless.
	if !strings.Contains(got, "<strong>") {
		t.Errorf("the message's own markup was escaped away, got %q", got)
	}
}

// An argument of a type substitution cannot render stays visible as its
// placeholder rather than becoming an empty hole.
//
// The two failure shapes look very different on a page: {Number} in the middle
// of a sentence is obviously wrong and names the field to fix; a blank where
// the number belonged reads as a finished sentence about nothing, and on a
// page asking somebody to confirm WHICH number a code went to, a hole is the
// worse failure. A float64 stands in for any type stringify does not know.
func TestAnUnsupportedArgumentTypeStaysVisible(t *testing.T) {
	b := load(t, "")

	got := string(b.For("en").T("smsotp.sent", map[string]any{
		"Number": 3.14,
	}))

	if !strings.Contains(got, "{Number}") {
		t.Errorf("an unrenderable argument should leave its placeholder visible, got %q", got)
	}
}

// Every catalogue we ship is complete.
//
// A partial translation is not a neutral state. The fallback makes the page
// render, so nothing breaks -- it just comes out half in one language and half
// in another, on a page asking somebody for their password. That reads as a
// compromised site to exactly the people we most want to be suspicious.
//
// An operator's own catalogue is deliberately allowed to be partial: they are
// layering onto a complete one. This is about what SHIPS.
func TestEveryShippedCatalogueIsComplete(t *testing.T) {
	b := load(t, "")

	for _, lang := range b.Languages() {
		missing := b.Missing(lang)
		if len(missing) == 0 {
			continue
		}
		show := missing
		if len(show) > 8 {
			show = show[:8]
		}
		t.Errorf("locales/%s.json is missing %d message(s), starting with %v.\n"+
			"    Either translate them or delete the catalogue: a half-translated "+
			"sign-in page is worse than an English one", lang, len(missing), show)
	}
}

// Every plural message defines every form its language actually uses.
//
// The fallback to "other" means a missing "few" still renders, in the wrong
// grammatical form, for a range of numbers nobody tests with. Arabic uses
// "few" for 3-10 -- a number a person genuinely sees -- so this checks the
// forms CLDR says the language needs, not a fixed list.
func TestEveryPluralMessageCoversItsLanguagesForms(t *testing.T) {
	b := load(t, "")

	// The counts that between them reach every CLDR category in the languages
	// shipped here.
	probes := []int{0, 1, 2, 3, 5, 11, 21, 100, 101}

	for _, lang := range b.Languages() {
		p := b.For(lang)
		for key, e := range b.msgs[lang] {
			if len(e.forms) == 1 {
				continue // Not a plural message.
			}
			for _, n := range probes {
				want := formName[cardinalForm(p, n)]
				if _, ok := e.forms[want]; !ok {
					t.Errorf("locales/%s.json: %q has no %q form, which %s uses "+
						"at n=%d; it will silently render the \"other\" form instead",
						lang, key, want, lang, n)
				}
			}
		}
	}
}

// A URL substituted into a message cannot execute.
//
// A message may contain a link, because "open {this link} on your other device"
// is one sentence in every language and three fragments if the anchor is pulled
// into the template. The cost is that T returns template.HTML, which skips the
// URL sanitising html/template does inside an href -- so this package has to do
// it, and this is what says so.
func TestAURLInAMessageCannotCarryAScheme(t *testing.T) {
	b := load(t, "")

	dangerous := []string{
		"javascript:alert(1)",
		"JaVaScRiPt:alert(1)",
		"java\tscript:alert(1)", // Tab-split, which some browsers still run.
		" javascript:alert(1)",
		"data:text/html;base64,PHNjcmlwdD4=",
		"vbscript:msgbox(1)",
	}
	for _, u := range dangerous {
		got := string(b.For("en").T("enrol.openlink", map[string]any{"URI": u}))
		// Asserting the REPLACEMENT rather than the absence of a substring.
		// Looking for "javascript:" would miss the tab-split spelling entirely,
		// and a test that cannot see the attack it names is worse than none.
		if !strings.Contains(got, `href="#"`) {
			t.Errorf("%q was not neutralised, href is: %s", u, got)
		}
	}

	// The real thing still works, or the guard has broken the feature.
	ok := string(b.For("en").T("enrol.openlink", map[string]any{
		"URI": "otpauth://totp/Example:amelia?secret=ABC",
	}))
	if !strings.Contains(ok, "otpauth://totp/Example:amelia") {
		t.Errorf("a legitimate otpauth URI was mangled: %s", ok)
	}
}

// A value substituted into a sentence keeps its own reading order.
//
// Found by looking at a rendered Arabic page. A masked number, +44 7700 •••912,
// in a right-to-left sentence displays as +44 7700 912••• -- the visible digits
// move to the wrong end, because the bullets are directionally neutral and
// resolve to the paragraph. The page that shows this is the one asking somebody
// to confirm which number their code went to.
func TestAValueKeepsItsOwnDirectionInsideASentence(t *testing.T) {
	b := load(t, "")

	const number = "+44 7700 •••912"
	got := string(b.For("ar").T("smsotp.sent", map[string]any{"Number": number}))

	if !strings.Contains(got, firstStrongIsolate+"+44 7700 •••912"+popDirectional) {
		t.Errorf("the number was not isolated, so it can be re-ordered by the "+
			"text around it: %q", got)
	}

	// In an attribute the isolates would end up inside the value itself.
	link := string(b.For("ar").T("enrol.openlink", map[string]any{
		"URI": "otpauth://totp/Example",
	}))
	if strings.Contains(link, firstStrongIsolate) {
		t.Errorf("an isolate was written into an attribute value: %q", link)
	}
	if !strings.Contains(link, `href="otpauth://totp/Example"`) {
		t.Errorf("the href was altered: %q", link)
	}
}

// A missing message renders English, and a missing English message renders the
// key.
//
// Neither is silent, and that is the point: a blank is a page with a hole in it
// that still looks finished.
func TestAMissingMessageFallsBackRatherThanBlanking(t *testing.T) {
	b := load(t, "")

	if got := string(b.For("en").T("no.such.key")); got != "no.such.key" {
		t.Errorf("an unknown key should render as itself, got %q", got)
	}
	// A language with no catalogue at all still renders English text.
	if got := string(b.For("zz").T("login.heading")); got != "Sign in" {
		t.Errorf("an unknown language should fall back to English, got %q", got)
	}
}

// ui_locales beats Accept-Language, and both beat the default.
func TestNegotiationPrefersWhatTheApplicationAskedFor(t *testing.T) {
	b := load(t, "")

	cases := []struct {
		name   string
		ui     string
		accept string
		want   string
	}{
		{"nothing asked", "", "", "en"},

		// The parameter exists so a relying party can say what the person
		// already chose in the application they came from. It has to beat the
		// browser's general setting, or it does nothing.
		{"ui_locales beats Accept-Language", "ar", "en-GB,en;q=0.9", "ar"},
		{"Accept-Language is used when ui_locales is absent", "", "ar", "ar"},

		// ui_locales is an ordered list, most preferred first.
		{"the first supported language in the list wins", "zz ar en", "", "ar"},
		{"unsupported entries are skipped, not fatal", "zz qq ar", "", "ar"},

		// Region subtags must resolve to the base language rather than falling
		// through: somebody asking for ar-EG should not get English because we
		// happen to have filed the catalogue as "ar".
		{"a region subtag resolves to the base language", "ar-EG", "", "ar"},
		{"and so does one in Accept-Language", "", "ar-MA,fr;q=0.8", "ar"},

		{"an unparseable ui_locales is skipped", "!!!!", "", "en"},
		{"a language we do not have falls back", "zz", "", "en"},
		{"a malformed Accept-Language does not fail the request", "", "\x00,,;q=", "en"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := b.Negotiate(tc.ui, tc.accept).Lang(); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// An operator can reword one sentence without forking anything.
func TestAnOperatorCanRewordASingleMessage(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "en.json", `{"login.heading": "Sign in to Example Corporation"}`)

	b := load(t, dir)

	if got := string(b.For("en").T("login.heading")); got != "Sign in to Example Corporation" {
		t.Errorf("the operator's wording was not used, got %q", got)
	}
	// Everything they did NOT mention still comes from the built-in catalogue.
	if got := string(b.For("en").T("login.title")); got != "Sign in" {
		t.Errorf("an untouched message changed, got %q", got)
	}
}

// A key that names no message is refused rather than kept.
//
// The same defect the theme loader had: accepting it means the operator
// believes they changed something they did not, and nothing ever tells them
// otherwise.
func TestAKeyNamingNoMessageIsReported(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "en.json", `{"login.headnig": "typo"}`)

	b, problems, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 {
		t.Fatalf("want exactly one problem, got %d: %v", len(problems), problems)
	}
	if !strings.Contains(problems[0].Error(), "login.headnig") {
		t.Errorf("the problem should name the key, got %v", problems[0])
	}
	if got := string(b.For("en").T("login.heading")); got != "Sign in" {
		t.Errorf("the real message should be untouched, got %q", got)
	}
}

// A broken file is refused; the rest of the server carries on.
func TestABrokenCatalogueIsRefusedRatherThanFatal(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "en.json", `{"login.heading": `) // truncated

	b, problems, err := Load(dir)
	if err != nil {
		t.Fatalf("a bad operator file must not be fatal: %v", err)
	}
	if len(problems) == 0 {
		t.Fatal("a truncated file was accepted silently")
	}
	if got := string(b.For("en").T("login.heading")); got != "Sign in" {
		t.Errorf("the built-in message should still render, got %q", got)
	}
}

// A plural message without "other" is refused.
func TestAPluralMessageMustDefineOther(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "en.json", `{"login.heading": {"one": "only one form"}}`)

	_, problems, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) == 0 {
		t.Fatal("a message with no \"other\" form was accepted")
	}
	if !strings.Contains(problems[0].Error(), "other") {
		t.Errorf("the problem should say what is missing, got %v", problems[0])
	}
}

// Direction comes from the script, so it is right for languages nobody listed.
func TestDirectionFollowsTheScript(t *testing.T) {
	b := load(t, "")
	for lang, want := range map[string]string{
		"en": "ltr", "fr": "ltr", "ja": "ltr",
		"ar": "rtl", "he": "rtl", "fa": "rtl", "ur": "rtl",
	} {
		p := &Printer{b: b, lang: lang, tag: language.Make(lang)}
		if got := p.Dir(); got != want {
			t.Errorf("%s: got dir=%q, want %q", lang, got, want)
		}
	}
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
