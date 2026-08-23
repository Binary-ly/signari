// Package pages holds every HTML page this server renders, as files rather
// than as Go string literals, so an operator can replace one without a compiler.
//
// # What was wrong with the old arrangement
//
// Thirty-three pages were built as `template.Must(template.New(...).Parse(
// `<!doctype html>…`))` across twenty-two Go files. Changing a heading, a
// wording, or the order of two paragraphs meant forking the repository and
// producing a binary that is no longer the one anybody audited.
//
// The brand was not the whole of it. `signari brand set` genuinely worked, and
// it reached twenty of the thirty-three pages — the ones rendered through
// `renderPage`. The other thirteen were rendered by calling `.Execute` directly,
// and among them were the CONSENT SCREEN and the TWO-FACTOR CHALLENGE: the two
// pages where a person is most explicitly asked to check that they are where
// they think they are. An operator set a logo, saw it on the sign-in form, and
// had no way to discover it was absent three clicks later.
//
// The comment above `renderPage` already stated the rule that was being broken:
//
//	"A sign-in page that ignores the brand while the consent page honours it does
//	not look like a missing feature -- it looks like the deployment has been
//	tampered with, which is the opposite of what branding is for."
//
// # How overriding works
//
// Two units, and the smaller one is the one most operators want:
//
//   - Override `layout.html` and you have replaced the CHROME — the head, the
//     header, the logo, the footer — for every page at once, while every form,
//     every hidden field and every button stays ours. This is the safe common
//     case and it cannot drop a CSRF token, because it never contained one.
//   - Override an individual page and you have replaced that page's content.
//     Powerful, and the reason Validate exists.
//
// # Why a broken override does not stop the server
//
// A theme that fails validation is refused PER PAGE and the built-in is used
// instead, loudly. The alternative — refusing to start — hands an operator the
// ability to lock every user out of every application by mistyping a filename
// at four in the afternoon. `signari theme check` exists so the failure is found
// in a pipeline instead, where stopping is the correct response.
//
// # Why overrides are read once, at startup
//
// Not per request. A half-written file is a normal state for a directory
// somebody is editing, and the pages here are the ones a person signs in
// through; serving one mid-save is worse than making the operator restart.
package pages

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"signari.dev/engine/internal/i18n"
)

//go:embed files
var builtin embed.FS

// Partials are shared fragments every page is parsed with.
//
// They are not pages and cannot be rendered on their own; a request for one by
// name is not found, the same as any other name that is not a page.
var partials = map[string]bool{
	"layout":  true,
	"bare":    true,
	"pagecss": true,
	"captcha": true,
}

// Set is every page, parsed and ready to render.
//
// Immutable once built. Load returns a new Set; nothing mutates one afterwards,
// so it is safe to share across every request without a lock.
type Set struct {
	// tmpl is language -> page -> template.
	//
	// One parsed tree per language rather than one shared tree, because Go
	// resolves a template function's NAME at parse time and its implementation
	// from the template it was parsed into. A single tree would mean rebinding
	// T on every request, which is a data race across concurrent sign-ins.
	//
	// The cost is bounded: a page's tree is proportional to how many actions it
	// has, not how long it is, so the 13KB stylesheet every page carries is one
	// text node in each copy.
	tmpl   map[string]map[string]*template.Template
	origin map[string]string
	// order is the page names, sorted, for anything that lists them.
	order []string
	// bundle is what T and N resolve against, and what discovery advertises.
	bundle *i18n.Bundle
}

// Load reads the built-in pages and, when overrideDir is not empty, replaces any
// page or partial that directory names.
//
// A page whose override fails Validate is reported in the returned []error and
// the built-in is kept. Load itself only fails for something that makes the
// whole set unusable — a built-in that will not parse, or an override directory
// that cannot be read at all.
func Load(overrideDir string) (*Set, []error, error) {
	src, err := builtinSources()
	if err != nil {
		return nil, nil, err
	}
	origin := map[string]string{}
	for name := range src {
		origin[name] = "built-in"
	}

	// Overrides are parsed into a COPY and validated before they are allowed to
	// replace anything, so a set is never briefly holding a page that failed.
	var problems []error
	if overrideDir != "" {
		over, err := overrideSources(overrideDir)
		if err != nil {
			return nil, nil, err
		}
		for name, body := range over {
			// A file naming nothing is a typo, and accepting it is worse than
			// refusing it: `logn.html` would otherwise become a thirty-fourth page
			// that no route renders, while `theme list` and `doctor` both counted it
			// as an override and reported success. `theme check` has always refused
			// this; Load must agree with it, or the check passing in CI and the
			// server accepting it mean different things.
			if _, known := src[name]; !known && !partials[name] {
				problems = append(problems, fmt.Errorf(
					"%s does not correspond to any page this server renders, so it "+
						"is being ignored; `signari theme list` prints every name",
					filepath.Join(overrideDir, name+".html")))
				continue
			}
			candidate := clone(src)
			candidate[name] = body
			if err := validateOne(candidate, name); err != nil {
				problems = append(problems, fmt.Errorf(
					"%s: the override was refused and the built-in page is being "+
						"used instead: %w", filepath.Join(overrideDir, name+".html"), err))
				continue
			}
			src[name] = body
			origin[name] = filepath.Join(overrideDir, name+".html")
		}
	}

	// The catalogue lives in the SAME directory as the pages, under locales/.
	//
	// One directory and one environment variable, because they are one thing to
	// an operator: what this deployment's sign-in pages say. Splitting them
	// would mean a theme that renders the right words in the wrong markup, or
	// the reverse, depending on which of two settings somebody remembered.
	var localeDir string
	if overrideDir != "" {
		localeDir = filepath.Join(overrideDir, "locales")
	}
	bundle, langProblems, err := i18n.Load(localeDir)
	if err != nil {
		return nil, problems, err
	}
	problems = append(problems, langProblems...)

	set, err := build(src, bundle)
	if err != nil {
		return nil, problems, err
	}
	set.origin = origin
	return set, problems, nil
}

// Bundle is the message catalogue these pages render against.
//
// Exposed so discovery can advertise ui_locales_supported from what is actually
// loaded rather than from a list somebody maintains alongside it.
func (s *Set) Bundle() *i18n.Bundle {
	if s == nil {
		return nil
	}
	return s.bundle
}

func clone(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func builtinSources() (map[string]string, error) {
	entries, err := fs.ReadDir(builtin, "files")
	if err != nil {
		return nil, fmt.Errorf("reading the built-in pages: %w", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		b, err := builtin.ReadFile("files/" + e.Name())
		if err != nil {
			return nil, err
		}
		out[strings.TrimSuffix(e.Name(), ".html")] = string(b)
	}
	if len(out) == 0 {
		// The embed directive silently produces an empty FS when the directory
		// moves, and every page would then be "not found" at render time -- a
		// blank sign-in form rather than an error anybody can act on.
		return nil, fmt.Errorf("no built-in pages were embedded; the files " +
			"directory is missing from the binary")
	}
	return out, nil
}

// overrideSources reads *.html from a directory, one level deep.
//
// Only the base name is used, so nothing a filename contains can reach outside
// the directory -- there is no path to traverse because no path is taken.
func overrideSources(dir string) (map[string]string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("the theme directory %q cannot be read: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("the theme directory %q is not a directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, filepath.Base(e.Name())))
		if err != nil {
			return nil, err
		}
		out[strings.TrimSuffix(e.Name(), ".html")] = string(b)
	}
	return out, nil
}

// build parses each page against the shared partials.
//
// One template set per page rather than one for everything: each page defines
// its own "content", and in a single namespace the last one parsed would win for
// all of them. Cloning the partials per page is what keeps `{{define "content"}}`
// meaning this page's content.
func build(src map[string]string, bundle *i18n.Bundle) (*Set, error) {
	set := &Set{
		tmpl:   map[string]map[string]*template.Template{},
		bundle: bundle,
	}

	for _, lang := range bundle.Languages() {
		printer := bundle.For(lang)

		base := template.New("base").Funcs(funcsFor(printer))
		for name, body := range src {
			if !partials[name] {
				continue
			}
			if _, err := base.Parse(body); err != nil {
				return nil, fmt.Errorf("the %s partial does not parse: %w", name, err)
			}
		}

		set.tmpl[lang] = map[string]*template.Template{}
		for name, body := range src {
			if partials[name] {
				continue
			}
			t, err := base.Clone()
			if err != nil {
				return nil, err
			}
			if _, err := t.New(name).Parse(body); err != nil {
				return nil, fmt.Errorf("the %s page does not parse: %w", name, err)
			}
			set.tmpl[lang][name] = t
		}
	}

	for name := range src {
		if !partials[name] {
			set.order = append(set.order, name)
		}
	}
	sort.Strings(set.order)
	return set, nil
}

// funcsFor is what a page may call, bound to one language.
//
// Deliberately small. Every function here is one an operator's override can
// also call, so each is a piece of API that has to keep working; a template
// function that reaches into request state or the database would make a theme
// able to do things a theme should not.
func funcsFor(p *i18n.Printer) template.FuncMap {
	return template.FuncMap{
		// T renders a message. `{{T "login.heading"}}`, or with the page's data
		// available for {Placeholder} substitution: `{{T "smsotp.sent" .}}`.
		"T": p.T,
		// N renders a message that counts something, choosing the plural form
		// CLDR specifies for this language. `{{N "fclogout.progress" (len .Targets)}}`
		"N": p.N,
		// The language being rendered and its direction, for <html lang dir>.
		"lang": p.Lang,
		"dir":  p.Dir,
	}
}

// Execute renders a page.
//
// The caller names a PAGE, never a template inside it, so which template is
// actually invoked -- the page itself, or a layout the page fills -- stays an
// implementation detail this package can change without touching a call site.
func (s *Set) Execute(w io.Writer, name string, data any) error {
	return s.ExecuteIn(w, i18n.Default, name, data)
}

// ExecuteIn renders a page in one language.
//
// An unknown language renders the default rather than failing. The language
// comes from a request parameter and an HTTP header, so it is a stranger's
// input reaching a code path that has to work: a person whose browser asks for
// something we do not have needs a sign-in page, not an error.
func (s *Set) ExecuteIn(w io.Writer, lang, name string, data any) error {
	// A nil Set has no pages. Answered rather than dereferenced, so a caller that
	// never loaded one logs "no page" per request instead of taking the process
	// down on the first sign-in.
	if s == nil {
		return fmt.Errorf("no pages are loaded, so %q cannot be rendered", name)
	}
	byPage, ok := s.tmpl[lang]
	if !ok {
		byPage = s.tmpl[i18n.Default]
	}
	t, ok := byPage[name]
	if !ok {
		return fmt.Errorf("there is no page named %q", name)
	}
	// A page that defines "content" is filling a layout; anything else renders
	// itself. Looking rather than recording it means a page and its override can
	// disagree about which style they are, which is what lets an operator replace
	// a laid-out page with a self-contained one.
	root := name
	if t.Lookup("content") != nil {
		root = layoutFor(t)
	}
	return t.ExecuteTemplate(w, root, data)
}

// layoutFor picks the chrome a page asked for.
//
// A page selects the bare layout by defining "bare" as a marker. The auto-posting
// bridges use it -- a SAML POST form and a front-channel logout frame are read by
// a browser and never by a person, so giving them a logo, a stylesheet and a
// footer would add two requests to a redirect nobody sees.
func layoutFor(t *template.Template) string {
	if t.Lookup("usebare") != nil {
		return "bare"
	}
	return "layout"
}

// Has reports whether a page exists.
func (s *Set) Has(name string) bool { _, ok := s.tmpl[name]; return ok }

// Names lists every page, sorted.
func (s *Set) Names() []string { return append([]string(nil), s.order...) }

// Origin says where a page came from: "built-in", or the file that replaced it.
//
// For `signari doctor` and `theme check`, so an operator can be told which of
// their files is live rather than having to infer it from what the page looks
// like.
func (s *Set) Origin(name string) string {
	if o, ok := s.origin[name]; ok {
		return o
	}
	return "built-in"
}

// BuiltIn returns the embedded page sources, keyed by name.
//
// For `signari theme eject`: an operator starting a theme copies the real page
// rather than a skeleton, so their first edit is a small one and every hidden
// field the validator will ask for is already in front of them.
func BuiltIn() map[string]string {
	src, err := builtinSources()
	if err != nil {
		return nil
	}
	return src
}
