package pages

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"signari.dev/engine/internal/i18n"
)

// The page set, its layout, and what an override is allowed to do to it.
//
// Two things are being defended here and they pull in opposite directions. An
// operator must be able to change what a page says, or they will fork the
// repository and run a binary nobody audited. And an operator must NOT be able
// to drop a CSRF token by accident, because the page still looks finished
// afterwards.

func loadOrFail(t *testing.T, dir string) *Set {
	t.Helper()
	set, problems, err := Load(dir)
	if err != nil {
		t.Fatalf("loading pages: %v", err)
	}
	if len(problems) > 0 {
		t.Fatalf("unexpected refusals: %v", problems)
	}
	return set
}

// Every built-in page renders, under every branch, with nothing missing.
//
// The probe drives each page through all fourteen datasets -- every branch off,
// every branch on, and one per boolean -- so a page whose form hides behind
// `{{else if .Confirm}}` is exercised rather than skipped.
func TestEveryBuiltInPageRenders(t *testing.T) {
	src, err := builtinSources()
	if err != nil {
		t.Fatal(err)
	}
	set := loadOrFail(t, "")
	if len(set.Names()) < 30 {
		t.Fatalf("only %d pages loaded; the embedded directory is not complete",
			len(set.Names()))
	}
	for _, name := range set.Names() {
		if _, err := requirementsOf(src, name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The defect this package exists for.
//
// `signari brand set` reached the twenty pages rendered through renderPage and
// not the thirteen that called Execute directly -- including the consent screen
// and the two-factor challenge. Those are the two pages where a person is most
// explicitly asked to check they are where they think they are, and they were
// the ones with no logo on them.
//
// The logo now lives in the layout, so the only way to lose it on one page is to
// lose it on all of them.
func TestEveryPageAPersonSeesCarriesTheBrand(t *testing.T) {
	src, err := builtinSources()
	if err != nil {
		t.Fatal(err)
	}
	set := loadOrFail(t, "")

	data := probeVariants()[1] // every branch on
	data["BrandLogo"] = "https://brand.example/logo.svg"
	data["BrandName"] = "Example Corporation"

	// The bridges a browser posts and nobody reads. Named individually rather
	// than detected, so adding a page cannot quietly opt itself out of carrying
	// the brand by looking like a bridge.
	//
	// fclogout is NOT one of them, though it was listed here at first. It has a
	// heading, a sentence telling a person how many applications they are being
	// signed out of, and a link to continue if one of those hangs. The hidden
	// iframes are its machinery; the page around them is read, so it carries the
	// brand like every other page a person sees.
	//
	// racview is bare for the opposite reason to the rest: it is looked at for a
	// long time, and what fills it is somebody else's desktop. Chrome around that
	// competes with the content, so it styles itself and carries no logo.
	bridges := map[string]bool{
		"saml": true, "formpost": true, "wsfed": true, "racview": true,
	}

	for _, name := range set.Names() {
		var sb strings.Builder
		if err := set.Execute(&sb, name, data); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got := strings.Contains(sb.String(), "https://brand.example/logo.svg")
		if bridges[name] {
			if got {
				t.Errorf("%s is an auto-posting bridge and should carry no logo: a "+
					"person never reads it, and the image is an extra request in the "+
					"middle of a sign-on", name)
			}
			continue
		}
		if !got {
			t.Errorf("%s does not render the configured logo. An operator who sets "+
				"one sees it on some pages and not others, which reads as a "+
				"tampered-with deployment rather than a missing feature", name)
		}
	}
	// The guard against this test passing vacuously: at least one bridge and a
	// good many ordinary pages must have been examined.
	if len(set.Names())-len(bridges) < 20 {
		t.Fatalf("only %d non-bridge pages; this test is not covering the set",
			len(set.Names())-len(bridges))
	}
	_ = src
}

// writeTheme puts files in a temporary directory and returns its path.
func writeTheme(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name+".html"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A theme that changes wording is accepted. This is the whole point.
func TestAThemeMayChangeWhatAPageSays(t *testing.T) {
	built, err := builtinSources()
	if err != nil {
		t.Fatal(err)
	}
	// Take the real login page and change only its heading, replacing the
	// message call with a literal. Still supported, and still a fork of the
	// page: see the catalogue test below for the cheaper way to do this.
	themed := strings.Replace(built["login"], `<h1>{{T "login.heading"}}</h1>`,
		"<h1>Welcome back to Example Corporation</h1>", 1)
	if themed == built["login"] {
		t.Fatal("the heading was not found, so this test would pass without " +
			"testing anything")
	}
	dir := writeTheme(t, map[string]string{"login": themed})

	set, problems, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) > 0 {
		t.Fatalf("a theme that only changed a heading was refused: %v", problems)
	}
	var sb strings.Builder
	if err := set.Execute(&sb, "login", probeVariants()[1]); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "Welcome back to Example Corporation") {
		t.Error("the themed heading is not in the rendered page")
	}
	if set.Origin("login") == "built-in" {
		t.Error("Origin still reports the built-in page")
	}
}

// Rewording without forking a page.
//
// The reason the catalogue is worth having beyond translation: changing one
// sentence used to mean copying a whole page into a theme directory, where it
// stopped receiving upstream fixes -- including security fixes to the form it
// contains. Now it is three lines of JSON, and the page stays ours.
func TestAnOperatorCanRewordAPageWithoutForkingIt(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "locales"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "locales", "en.json"),
		[]byte(`{"login.heading": "Welcome back to Example Corporation"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	set := loadOrFail(t, dir)

	var sb strings.Builder
	if err := set.Execute(&sb, "login", probeVariants()[1]); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "Welcome back to Example Corporation") {
		t.Error("the operator's wording is not in the rendered page")
	}
	// The page itself was never overridden, so it still receives upstream fixes.
	if got := set.Origin("login"); got != "built-in" {
		t.Errorf("rewording should not fork the page, but Origin says %q", got)
	}
	// And nothing else on the page changed.
	if !strings.Contains(sb.String(), "Username or email") {
		t.Error("an untouched message on the same page changed")
	}
}

// The refusals. Each drops exactly one thing from an otherwise working page.
func TestAThemeMayNotDropWhatMakesThePageSafe(t *testing.T) {
	built, err := builtinSources()
	if err != nil {
		t.Fatal(err)
	}
	csrfLine := regexp.MustCompile(`<input type="hidden" name="\{\{\.CSRFField\}\}"[^>]*>`)

	cases := []struct {
		name    string
		page    string
		spoil   func(string) string
		mustSay string
	}{
		{
			name: "the CSRF token", page: "login",
			spoil:   func(s string) string { return csrfLine.ReplaceAllString(s, "") },
			mustSay: "CSRF",
		},
		{
			name: "the parked authorization request", page: "login",
			spoil: func(s string) string {
				return strings.Replace(s,
					`<input type="hidden" name="authz" value="{{.Authz}}">`, "", 1)
			},
			mustSay: "Authz",
		},
		{
			name: "where the form posts", page: "login",
			spoil: func(s string) string {
				return strings.Replace(s, `action="/login"`, `action="#"`, 1)
			},
			mustSay: "/login",
		},
		{
			name: "the SAML response", page: "saml",
			spoil: func(s string) string {
				return strings.Replace(s,
					`<input type="hidden" name="SAMLResponse" value="{{.Response}}">`, "", 1)
			},
			mustSay: "Response",
		},
		{
			// The form_post response mode builds its hidden inputs from data, so
			// there is no field name to look for -- only that the loop is still
			// there. A theme that drops it renders a form that posts nothing.
			name: "the loop that emits the response parameters", page: "formpost",
			spoil: func(s string) string {
				return regexp.MustCompile(`(?s)\{\{range \.Fields\}\}.*?\{\{end\}\}`).
					ReplaceAllString(s, "")
			},
			mustSay: "hidden input",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spoiled := tc.spoil(built[tc.page])
			if spoiled == built[tc.page] {
				t.Fatal("the page was not modified, so this test proves nothing")
			}
			dir := writeTheme(t, map[string]string{tc.page: spoiled})

			set, problems, err := Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(problems) == 0 {
				t.Fatalf("a theme that dropped %s was accepted", tc.name)
			}
			if msg := problems[0].Error(); !strings.Contains(msg, tc.mustSay) {
				t.Errorf("the refusal does not name what was lost (%q): %s",
					tc.mustSay, msg)
			}
			// And the built-in is serving, so the deployment is not broken.
			if set.Origin(tc.page) != "built-in" {
				t.Errorf("the refused override is live; Origin says %q",
					set.Origin(tc.page))
			}
			var sb strings.Builder
			if err := set.Execute(&sb, tc.page, probeVariants()[1]); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(sb.String(), "action=\"#\"") {
				t.Error("the refused markup is being rendered")
			}
		})
	}
}

// Overriding the LAYOUT is the common case and must not need a page rewritten.
func TestOverridingTheLayoutRestylesEveryPage(t *testing.T) {
	built, err := builtinSources()
	if err != nil {
		t.Fatal(err)
	}
	themed := strings.Replace(built["layout"], "<body>",
		`<body><div id="example-corp-chrome">`, 1)
	themed = strings.Replace(themed, "</body>", "</div></body>", 1)
	dir := writeTheme(t, map[string]string{"layout": themed})

	set, problems, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) > 0 {
		t.Fatalf("a layout that only added a wrapper was refused: %v", problems)
	}
	for _, name := range []string{"login", "consent", "mfa", "device"} {
		var sb strings.Builder
		if err := set.Execute(&sb, name, probeVariants()[1]); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(sb.String(), "example-corp-chrome") {
			t.Errorf("%s did not pick up the overridden layout", name)
		}
	}
}

// A layout that drops the content is refused, and refused for every page.
func TestALayoutThatSwallowsTheContentIsRefused(t *testing.T) {
	built, err := builtinSources()
	if err != nil {
		t.Fatal(err)
	}
	themed := strings.Replace(built["layout"], `{{template "content" .}}`, "", 1)
	if themed == built["layout"] {
		t.Fatal("the content hook was not found")
	}
	dir := writeTheme(t, map[string]string{"layout": themed})
	_, problems, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) == 0 {
		t.Fatal("a layout that renders no page content was accepted; every form " +
			"in the product would have vanished")
	}
}

// A file naming a page this server does not have is reported, not ignored.
func TestCheckReportsAFileThatWouldDoNothing(t *testing.T) {
	dir := writeTheme(t, map[string]string{
		"lgoin": `{{define "content"}}<p>typo</p>{{end}}`,
	})
	_, problems := Check(dir)
	if len(problems) == 0 {
		t.Fatal("a misnamed theme file was accepted silently, which is how " +
			"somebody spends an afternoon wondering why their theme does nothing")
	}
	if !strings.Contains(problems[0].Error(), "lgoin") {
		t.Errorf("the report does not name the file: %v", problems[0])
	}
}

// Only the base name of a theme file is used, so nothing can reach outside.
func TestOverridesCannotEscapeTheirDirectory(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(dir, "theme")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "login.html"),
		[]byte(`{{define "content"}}ESCAPED{{end}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory inside the theme dir is skipped, not descended into.
	if err := os.MkdirAll(filepath.Join(inner, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, "nested", "login.html"),
		[]byte(`{{define "content"}}NESTED{{end}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	set := loadOrFail(t, inner)
	var sb strings.Builder
	if err := set.Execute(&sb, "login", probeVariants()[1]); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sb.String(), "ESCAPED") || strings.Contains(sb.String(), "NESTED") {
		t.Error("a file outside the theme directory was loaded")
	}
}

// criticalFields must not fall behind the pages.
//
// The requirement is derived from the built-in, which means a NEW field is
// protected the moment it appears -- but only if the field is on the list. This
// is what keeps the list from rotting: every value the built-in pages put in a
// hidden input has to be here, or explicitly waived below.
func TestCriticalFieldsCoversEveryHiddenInput(t *testing.T) {
	src, err := builtinSources()
	if err != nil {
		t.Fatal(err)
	}
	// name="..." value="{{.X}}" — the fields a form carries invisibly.
	hidden := regexp.MustCompile(
		`<input[^>]*type="hidden"[^>]*value="\{\{\s*\$?\.([A-Za-z][A-Za-z0-9_]*)\s*\}\}"`)

	// Values that are deliberately not critical, with the reason.
	// Only the two loop variables. Everything else that reaches a hidden input
	// is critical -- see criticalFields, which this test grew by six.
	waived := map[string]string{
		// `{{range .Fields}}<input name="{{.Name}}" value="{{.Value}}">` in the
		// form_post, SAML and WS-Federation bridges. These are the loop's own
		// variables rather than fields of the page, so there is no fixed value to
		// require; the hidden-input COUNT is what protects the loop itself.
		"Name":  "the response-parameter loop's own variable, not a page field",
		"Value": "the response-parameter loop's own variable, not a page field",
	}

	missing := map[string]string{}
	for name, body := range src {
		if partials[name] {
			continue
		}
		for _, m := range hidden.FindAllStringSubmatch(body, -1) {
			f := m[1]
			if contains(criticalFields, f) || waived[f] != "" {
				continue
			}
			missing[f] = name
		}
	}
	if len(missing) > 0 {
		var lines []string
		for f, page := range missing {
			lines = append(lines, f+" (on the "+page+" page)")
		}
		t.Errorf("%d hidden field(s) are neither in criticalFields nor waived:\n  %s\n\n"+
			"A theme could drop these and the override would still be accepted. Add "+
			"each to criticalFields, or to the waived map with the reason it does "+
			"not matter.", len(missing), strings.Join(lines, "\n  "))
	}
}

// Origin tells an operator which file is live.
func TestOriginNamesTheFileInForce(t *testing.T) {
	built, err := builtinSources()
	if err != nil {
		t.Fatal(err)
	}
	dir := writeTheme(t, map[string]string{"consent": built["consent"]})
	set := loadOrFail(t, dir)
	if got := set.Origin("consent"); !strings.HasSuffix(got, "consent.html") {
		t.Errorf("Origin(consent) = %q, want the override path", got)
	}
	if got := set.Origin("login"); got != "built-in" {
		t.Errorf("Origin(login) = %q, want built-in", got)
	}
}

// A partial cannot be rendered as though it were a page.
func TestPartialsAreNotPages(t *testing.T) {
	set := loadOrFail(t, "")
	for name := range partials {
		if set.Has(name) {
			t.Errorf("%q is reachable as a page", name)
		}
		var sb strings.Builder
		if err := set.Execute(&sb, name, probeVariants()[0]); err == nil {
			t.Errorf("%q rendered as a page", name)
		}
	}
}

// A nil Set answers rather than panicking.
func TestANilSetAnswersInsteadOfPanicking(t *testing.T) {
	var s *Set
	var sb strings.Builder
	if err := s.Execute(&sb, "login", nil); err == nil {
		t.Fatal("a nil Set rendered something")
	}
}

// A critical field read INSIDE a range is protected too.
//
// The backchannel approval page loops over pending requests and puts each one's
// id in a hidden input, so the sentinel has to reach the loop element -- not
// just the top-level data -- or no requirement is derived and the field could be
// dropped freely.
func TestAFieldInsideALoopIsStillProtected(t *testing.T) {
	built, err := builtinSources()
	if err != nil {
		t.Fatal(err)
	}
	// The input STAYS and only its value is emptied, so the hidden-input count is
	// unchanged. Deleting the whole line would be caught by the count rule and
	// this test would pass with the sentinel machinery removed -- which is what
	// it did until mutation said so.
	spoiled := strings.Replace(built["backchannel"],
		`<input type="hidden" name="id" value="{{.ID}}">`,
		`<input type="hidden" name="id" value="">`, 1)
	if spoiled == built["backchannel"] {
		t.Fatal("the id field was not found, so this test proves nothing")
	}
	_, problems, err := Load(writeTheme(t, map[string]string{"backchannel": spoiled}))
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) == 0 {
		t.Fatal("a theme that dropped the id of the request being approved was " +
			"accepted: the approval form would post without saying what it approves")
	}
}

// A branch that only renders in the middle of an if/else-if chain is probed.
//
// The device page hides its approval form behind `{{else if .Confirm}}`. Probed
// only with everything true it never renders, and a requirement derived from
// that would let a theme drop the form entirely.
func TestAFormInAMiddleBranchIsStillProtected(t *testing.T) {
	built, err := builtinSources()
	if err != nil {
		t.Fatal(err)
	}
	spoiled := strings.Replace(built["device"],
		`<input type="hidden" name="user_code" value="{{.UserCode}}">`, "", 1)
	if spoiled == built["device"] {
		t.Fatal("the user_code field was not found, so this test proves nothing")
	}
	_, problems, err := Load(writeTheme(t, map[string]string{"device": spoiled}))
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) == 0 {
		t.Fatal("a theme that dropped the code identifying the device being " +
			"approved was accepted, because the branch it lives in was never probed")
	}
}

// A theme that only works when there is data to show is refused.
//
// This is what the all-branches-off probe is for. An empty list is an ordinary
// state -- nobody has connected an application yet, there are no pending
// requests -- and a theme that reaches into one is a page that breaks for
// exactly the people who have not used the product yet.
func TestAThemeThatBreaksOnEmptyDataIsRefused(t *testing.T) {
	built, err := builtinSources()
	if err != nil {
		t.Fatal(err)
	}
	spoiled := strings.Replace(built["connected"], `{{define "content"}}`,
		`{{define "content"}}<p>First: {{(index .Apps 0).Name}}</p>`, 1)
	if spoiled == built["connected"] {
		t.Fatal("the content block was not found, so this test proves nothing")
	}
	_, problems, err := Load(writeTheme(t, map[string]string{"connected": spoiled}))
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) == 0 {
		t.Fatal("a theme that indexes an empty list was accepted; it renders for " +
			"anybody with a connected application and fails for everybody else")
	}
}

// A DIRECTORY named like a page does not take the whole set down.
//
// os.ReadFile on a directory is an error, and overrideSources returning one
// makes Load fail entirely -- so a stray `login.html/` would stop the server
// rather than being skipped.
func TestADirectoryNamedLikeAPageIsSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "login.html"), 0o700); err != nil {
		t.Fatal(err)
	}
	set, problems, err := Load(dir)
	if err != nil {
		t.Fatalf("a directory named login.html stopped the page set loading: %v", err)
	}
	if len(problems) > 0 {
		t.Errorf("unexpected refusals: %v", problems)
	}
	if set.Origin("login") != "built-in" {
		t.Error("the built-in login page is not in force")
	}
}

// A misspelled filename is the likeliest theming mistake there is, and the two
// code paths that see it used to disagree: `theme check` refused it, while Load
// -- the path the running server takes -- accepted it as a brand new page that
// no route renders, leaving `theme list` and `doctor` both reporting "1
// overridden" as though it had worked.
//
// A check that passes in CI and a server that accepts the same directory must
// mean the same thing, or the check is worse than nothing: it teaches an
// operator to trust a result that does not hold.
func TestAFileNamingNoPageIsRefusedRatherThanBecomingOne(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "logn.html"),
		[]byte(`{{define "content"}}<p>typo</p>{{end}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	set, problems, err := Load(dir)
	if err != nil {
		t.Fatalf("a misnamed file stopped the page set loading: %v", err)
	}
	if len(problems) != 1 {
		t.Fatalf("a file naming no page produced %d refusal(s), want 1: %v",
			len(problems), problems)
	}
	if !strings.Contains(problems[0].Error(), "logn.html") {
		t.Errorf("the refusal does not name the file that is wrong: %v", problems[0])
	}
	if set.Has("logn") {
		t.Error("the misnamed file became a page nothing renders, which is the " +
			"defect: an operator sees it counted as an override and believes their " +
			"theme is live")
	}

	// And the two paths must agree, which is the property that actually broke.
	_, checked := Check(dir)
	if len(checked) != len(problems) {
		t.Errorf("theme check reports %d problem(s) and the server reports %d; "+
			"a passing check must mean the server will accept it",
			len(checked), len(problems))
	}
}

// Presence is not the property; presence exactly once is.
//
// When the logo moved into the layout, login.html kept its own copy, so the
// sign-in page -- the single most-looked-at page here -- rendered the logo
// twice, one above the other. TestEveryPageAPersonSeesCarriesTheBrand passed
// throughout, because it asked whether the logo was there and a page with two
// of them answers yes.
func TestTheLogoAppearsExactlyOnce(t *testing.T) {
	set := loadOrFail(t, "")
	data := probeVariants()[1]
	data["BrandLogo"] = "https://brand.example/logo.svg"
	data["BrandName"] = "Example Corporation"

	for _, name := range set.Names() {
		var sb strings.Builder
		if err := set.Execute(&sb, name, data); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if n := strings.Count(sb.String(), "https://brand.example/logo.svg"); n > 1 {
			t.Errorf("%s renders the logo %d times. A page with the brand stacked on "+
				"itself is not a branded page, it is a broken one", name, n)
		}
	}
}

// The layout emits the shared stylesheet. A page that also asks for it ships
// every rule twice.
//
// Thirteen pages did exactly that after the move to files, because each one had
// carried `<style>{{template "pagecss" .}}</style>` from when there was no
// layout to put it in. Identical rules twice is not a rendering bug, which is
// why nothing caught it -- it is just every sign-in page paying for a stylesheet
// it already had.
func TestNoPageShipsTheStylesheetTwice(t *testing.T) {
	set := loadOrFail(t, "")
	data := probeVariants()[1]

	// A rule that appears once in the stylesheet and nowhere else in any page.
	const marker = "-webkit-font-smoothing:antialiased"

	for _, name := range set.Names() {
		var sb strings.Builder
		if err := set.Execute(&sb, name, data); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if n := strings.Count(sb.String(), marker); n > 1 {
			t.Errorf("%s includes the shared stylesheet %d times. The layout already "+
				"emits it; the page should define only what is its own", name, n)
		}
	}
}

// Every page in the set is reached by a handler.
//
// The defect: racview.html was written, validated, restyled, listed by
// `theme list` and emitted by `theme eject` -- and rendered by nothing. The
// handler still executed a template literal in internal/rac, so the viewer an
// operator themed was not the viewer anybody saw, and the theme surface
// reported an override that could not take effect.
//
// A page nothing serves is worse than a missing one. A missing page is a
// compile error or a 404; this one answers every question about itself
// correctly while being dead, which is the failure mode the whole theming
// system exists to remove.
//
// Scanning source is crude, and it is the only place the fact lives: which
// template a handler renders is not visible from inside this package.
func TestEveryPageIsServedBySomething(t *testing.T) {
	set := loadOrFail(t, "")

	// The call sites that put a page in front of a person. A page named in any
	// of them is served; a page named in none of them is not.
	// Bounded to one line and to a short distance, rather than "anything but a
	// closing paren": an argument may itself be a call -- s.langFor(r) -- and a
	// pattern that stopped at the first ')' reported those pages as dead.
	render := regexp.MustCompile(`(?:renderPage|renderBare|writeBranded|Execute|ExecuteIn)\(` +
		`[^\n]{0,80}?"([a-z]+)"`)

	// Only the server counts, and internal/httpapi is the whole of it.
	//
	// Scanning the tree broadly instead looks safer and is not: internal/rac's
	// browser harness renders racview deliberately, so a dev tool nobody
	// deploys was enough to vouch for the dead page. Verified by mutation --
	// with the scan widened, pointing the real handler at another template
	// leaves this test passing.
	//
	// If handlers ever live somewhere else, this fails loudly and gets a second
	// directory. That is the right direction to fail in.
	served := map[string]bool{}
	dir := filepath.Join("..", "httpapi")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the server package: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		for _, m := range render.FindAllSubmatch(b, -1) {
			served[string(m[1])] = true
		}
	}
	if len(served) == 0 {
		t.Fatal("found no render call sites at all; the scan is broken, not the code")
	}

	for _, name := range set.Names() {
		if !served[name] {
			t.Errorf("no handler renders %q, so the page is dead: `theme eject` "+
				"writes it, `theme check` validates it and `theme list` will call "+
				"it overridden, but nothing puts it in front of anybody", name)
		}
	}
}

// The pages and the catalogue agree, in both directions.
//
// A key a page asks for and the catalogue does not have renders as the key --
// `login.heading` in place of "Sign in" -- which is visible but only to whoever
// loads that page in that state. A key the catalogue has and no page asks for
// is a message a translator will be asked to translate for nothing, and a
// signal that a page was reworded without anyone tidying up after it.
//
// Both directions, because each failure is silent in its own way.
func TestEveryMessageKeyIsUsedAndEveryUsedKeyExists(t *testing.T) {
	src, err := builtinSources()
	if err != nil {
		t.Fatal(err)
	}
	bundle, _, err := i18n.Load("")
	if err != nil {
		t.Fatal(err)
	}

	// {{T "key"}} and {{N "key" ...}} in a template.
	call := regexp.MustCompile(`\{\{\s*[TN]\s+"([^"]+)"`)

	used := map[string]bool{}
	for name, body := range src {
		for _, m := range call.FindAllStringSubmatch(body, -1) {
			used[m[1]] = true
			if !bundle.HasKey(m[1]) {
				t.Errorf("%s.html asks for %q, which is not in "+
					"internal/i18n/locales/en.json, so the page renders the key",
					name, m[1])
			}
		}
	}

	// Not every message lives in a template. "That code did not match" is a
	// branch in a handler, so the Go that renders into a page counts as a user
	// of a key just as much as the page does -- and a check that only read
	// templates would call every one of those an orphan.
	goCall := regexp.MustCompile(`\.[TN]\("([^"]+)"`)
	for _, key := range keysUsedInGo(t, goCall) {
		used[key] = true
		if !bundle.HasKey(key) {
			t.Errorf("Go asks for the message %q, which is not in "+
				"internal/i18n/locales/en.json", key)
		}
	}

	// A third way a key gets used, and the one that is easiest to lose track
	// of: written as a bare literal because it is STORED and resolved later.
	// The password-change reasons are keys in a database column, looked up by
	// value when the page renders, so no .T("reason.breached") ever appears.
	//
	// Any dotted lowercase literal counts. Loose, deliberately: the cost of a
	// false "used" is one orphan going unreported, and the cost of a false
	// orphan is somebody deleting a message the product depends on.
	bare := regexp.MustCompile(`"([a-z][a-z0-9]*(?:\.[a-z0-9_]+)+)"`)
	for _, key := range keysUsedInGo(t, bare) {
		used[key] = true
	}

	// Some keys are composed rather than written out: the consent screen looks
	// up "scope."+name, so no literal "scope.profile" appears anywhere. Finding
	// the PREFIX in the source is what keeps those from reading as orphans
	// without having to hand-maintain an exemption list that goes stale.
	prefixes := dynamicKeyPrefixes(t)

	for _, key := range bundle.Keys() {
		if used[key] {
			continue
		}
		composed := false
		for _, p := range prefixes {
			if strings.HasPrefix(key, p) {
				composed = true
				break
			}
		}
		if composed {
			continue
		}
		t.Errorf("%q is in en.json and no page uses it. Delete it, or find "+
			"the page that should be asking for it", key)
	}

	// The guard against this passing because nothing was scanned.
	if len(used) < 50 {
		t.Fatalf("only %d keys found in the pages; this test is not covering "+
			"the set", len(used))
	}
}

// Scope descriptions are translated, and unknown scopes are not invented.
//
// The consent screen is the one page where the TEXT is the decision. A screen
// whose chrome is in the reader's language and whose list of what is being
// granted is in English asks somebody to approve something they cannot read --
// which is the exact situation consent exists to prevent.
//
// The second half matters as much: a scope a client registered is that
// client's words, and we neither translate nor gloss it. Showing "invoices.read"
// verbatim is honest; guessing at it would not be.
func TestScopeDescriptionsAreTranslatedAndUnknownOnesAreLeftAlone(t *testing.T) {
	bundle, _, err := i18n.Load("")
	if err != nil {
		t.Fatal(err)
	}

	for _, lang := range bundle.Languages() {
		p := bundle.For(lang)

		// Every scope the server describes must be describable in every
		// language it ships, or the consent screen is half-translated.
		for _, scope := range []string{
			"profile", "email", "offline_access", "address", "phone",
		} {
			if !p.Has("scope." + scope) {
				t.Errorf("%s has no description for the %q scope, so a consent "+
					"screen in that language lists it in English", lang, scope)
			}
		}

		// And one nobody registered stays exactly as it was written.
		const registered = "invoices.read"
		if p.Has("scope." + registered) {
			t.Errorf("%q has a built-in description, but a client-registered "+
				"scope is the client's words to choose", registered)
		}
	}
}

// No page has English written into it.
//
// The whole catalogue is worthless if one page keeps its sentences inline: that
// page renders English inside an otherwise translated flow, which is worse than
// an untranslated product because it looks like a bug in the translation rather
// than a missing feature.
//
// Text NODES only -- what sits between tags. Attributes are checked separately
// below, because most of them are machine-facing and a rule that flagged
// autocomplete="one-time-code" would be turned off within a week.
func TestNoPageHasEnglishWrittenIntoIt(t *testing.T) {
	src, err := builtinSources()
	if err != nil {
		t.Fatal(err)
	}

	// Two or more words made of letters. One word is usually a symbol, a unit,
	// or something like "OK" that a translator would leave alone anyway; two in
	// a row is a sentence somebody wrote.
	prose := regexp.MustCompile(`[A-Za-z][a-z]{2,}\s+[A-Za-z][a-z]{2,}`)

	for name, body := range src {
		if name == "pagecss" {
			continue // A stylesheet. No text nodes at all.
		}
		for _, text := range textNodes(body) {
			if m := prose.FindString(text); m != "" {
				t.Errorf("%s.html has English in it: %q\n"+
					"    Move it to internal/i18n/locales/en.json and render it "+
					"with {{T \"%s.something\"}}", name, trim(text), name)
				break // One report per page is enough to act on.
			}
		}
	}
}

// dynamicKeyPrefixes finds key prefixes the server concatenates at runtime.
//
// Matches `"scope." + something`, which is how a family of keys gets asked for
// without any one of them appearing as a literal.
func dynamicKeyPrefixes(t *testing.T) []string {
	t.Helper()

	concat := regexp.MustCompile(`"([a-z][a-z0-9]*\.)"\s*\+`)
	var out []string
	for _, key := range keysUsedInGo(t, concat) {
		out = append(out, key)
	}
	return out
}

// keysUsedInGo finds message keys asked for from handler code.
func keysUsedInGo(t *testing.T, call *regexp.Regexp) []string {
	t.Helper()

	var out []string
	// adminapi as well as httpapi: the Admin API sets a password-change reason,
	// and that reason is a message key rendered on a page this package owns.
	for _, pkg := range []string{"httpapi", "adminapi"} {
		dir := filepath.Join("..", pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading internal/%s: %v", pkg, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
				strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("reading %s: %v", e.Name(), err)
			}
			for _, m := range call.FindAllSubmatch(b, -1) {
				out = append(out, string(m[1]))
			}
		}
	}
	return out
}

// textNodes returns what a reader sees, with everything else removed.
func textNodes(body string) []string {
	// Order matters: comments first, because a commented-out tag would
	// otherwise leave its text behind.
	body = regexp.MustCompile(`(?s)\{\{/\*.*?\*/\}\}`).ReplaceAllString(body, " ")
	body = regexp.MustCompile(`(?s)<style.*?</style>`).ReplaceAllString(body, " ")
	body = regexp.MustCompile(`(?s)<script.*?</script>`).ReplaceAllString(body, " ")
	body = regexp.MustCompile(`(?s)<!--.*?-->`).ReplaceAllString(body, " ")
	// Template actions are not text: {{T "x"}} and {{.Error}} both render
	// something, and neither is a string written into this file.
	body = regexp.MustCompile(`(?s)\{\{.*?\}\}`).ReplaceAllString(body, " ")
	body = regexp.MustCompile(`(?s)<[^>]*>`).ReplaceAllString(body, "\n")

	var out []string
	for _, line := range strings.Split(body, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func trim(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}

// No page fetches anything from another origin.
//
// A font, a script or an image loaded from somebody else's host tells that host
// the IP address of every person signing in here, and when. An egress firewall
// does not touch it, because the connection is the browser's rather than ours.
// It is also a page that stops rendering correctly when a CDN has a bad day, on
// the one screen that has to work while other things are broken.
//
// The captcha partial is the documented exception and the reason this checks
// for an allowed set rather than for zero: a captcha script IS the service, so
// a copy served from here would produce a challenge nothing could verify.
// docs/egress-inventory.md carries the same list.
//
// Sources rather than rendered output on purpose. Pages legitimately DISPLAY
// absolute URLs -- a logout page names the applications being signed out of --
// and those are content. Only attributes that make the browser fetch something
// are asset references.
func TestNoPageLoadsAnythingFromAnotherOrigin(t *testing.T) {
	src, err := builtinSources()
	if err != nil {
		t.Fatal(err)
	}

	// Only the attributes that cause a fetch, plus CSS url().
	asset := regexp.MustCompile(`(?i)(?:<script[^>]+src|<link[^>]+href|` +
		`<img[^>]+src|<iframe[^>]+src|@import\s+|url\()\s*=?\s*["']?([a-z]+:)?//([^"')\s>]+)`)

	// The captcha providers, and nothing else.
	allowed := map[string]bool{
		"challenges.cloudflare.com": true,
		"hcaptcha.com":              true,
		"www.google.com":            true,
	}

	for name, body := range src {
		for _, m := range asset.FindAllStringSubmatch(body, -1) {
			host := m[2]
			if i := strings.IndexAny(host, "/?"); i >= 0 {
				host = host[:i]
			}
			// A template action rather than a literal host -- a brand logo is
			// operator-supplied and cannot be judged here.
			if strings.Contains(host, "{{") {
				continue
			}
			if allowed[host] {
				if name != "captcha" {
					t.Errorf("%s loads %s. The captcha providers belong only in "+
						"the captcha partial, where the exception is documented",
						name, host)
				}
				continue
			}
			t.Errorf("%s loads an asset from %s. Every page here is same-origin "+
				"on purpose: an off-origin fetch tells that host who is signing "+
				"in and when, and breaks the page when the host is down. Vendor "+
				"it, or add it to docs/egress-inventory.md and to this test",
				name, host)
		}
	}
}
