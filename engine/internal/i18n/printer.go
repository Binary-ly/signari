package i18n

import (
	"html/template"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/text/feature/plural"
	"golang.org/x/text/language"
)

// Printer renders messages in one language.
//
// Bound once per request rather than consulted per message, because the
// language is a property of the person reading the page and must not change
// halfway down it.
type Printer struct {
	b    *Bundle
	lang string
	tag  language.Tag
}

// For returns a printer for a named language, falling back to the default.
func (b *Bundle) For(lang string) *Printer {
	if b == nil {
		return &Printer{lang: Default, tag: language.English}
	}
	if _, ok := b.msgs[lang]; !ok {
		lang = Default
	}
	return &Printer{b: b, lang: lang, tag: language.Make(lang)}
}

// Negotiate picks the language for a request.
//
// The order is deliberate and is the part of this package most likely to be
// argued with, so the reasoning is here rather than in a commit message:
//
//  1. uiLocales -- the OIDC `ui_locales` request parameter. The relying party
//     asked for this explicitly, usually because the person already chose a
//     language in the application they came from. Being sent to a sign-in page
//     in a different language than the app that sent you is the failure this
//     parameter exists to prevent.
//  2. Accept-Language -- what the browser was configured with. A real
//     preference, but a general one, and often just the OS default.
//  3. The deployment default, then English.
//
// Both inputs are untrusted strings off the wire. Neither can do anything worse
// than fail to parse, and a tag we do not have falls through rather than
// erroring: a person with an unusual locale gets English, not a 400.
func (b *Bundle) Negotiate(uiLocales, acceptLanguage string) *Printer {
	if b == nil {
		return &Printer{lang: Default, tag: language.English}
	}

	// ui_locales is space-separated BCP-47, most preferred first. Taken one at a
	// time rather than handed to the matcher together, because the matcher
	// weighs its candidates and this list is an explicit ORDER.
	for _, want := range strings.Fields(uiLocales) {
		tag, err := language.Parse(want)
		if err != nil {
			continue
		}
		if name, ok := b.exact(tag); ok {
			return b.For(name)
		}
	}

	if acceptLanguage != "" {
		if tags, _, err := language.ParseAcceptLanguage(acceptLanguage); err == nil {
			if _, i, conf := b.matcher.Match(tags...); conf != language.No {
				return b.For(b.names[i])
			}
		}
	}

	return b.For(Default)
}

// exact resolves a requested tag to a loaded language.
//
// Matching runs through x/text so that a request for pt-BR is satisfied by pt,
// and en-GB by en, rather than falling to the default because the string did
// not compare equal.
func (b *Bundle) exact(want language.Tag) (string, bool) {
	_, i, conf := b.matcher.Match(want)
	if conf == language.No {
		return "", false
	}
	return b.names[i], true
}

// Lang is the BCP-47 tag of what is being rendered, for <html lang>.
func (p *Printer) Lang() string { return p.lang }

// Has reports whether a message exists to render.
//
// For the callers whose text is only SOMETIMES ours: a consent screen
// describes the scopes it knows and shows the raw name for the rest, so it has
// to ask before it renders rather than fall back to printing a key.
func (p *Printer) Has(key string) bool { return p.b.HasKey(key) }

// Dir is "rtl" or "ltr", for <html dir>.
//
// Decided by the language's SCRIPT rather than by a list of languages, because
// the property belongs to the writing system: Kurdish is right-to-left in
// Arabic script and left-to-right in Latin, and a per-language list gets that
// wrong in whichever direction it was written.
func (p *Printer) Dir() string {
	script, conf := p.tag.Script()
	if conf == language.No {
		return "ltr"
	}
	if rtlScript[script.String()] {
		return "rtl"
	}
	return "ltr"
}

// The right-to-left scripts, by ISO 15924 code.
var rtlScript = map[string]bool{
	"Adlm": true, "Arab": true, "Aran": true, "Rohg": true, "Hebr": true,
	"Mand": true, "Mend": true, "Nkoo": true, "Samr": true, "Syrc": true,
	"Thaa": true, "Yiii": false,
}

// T renders a message.
//
// The returned value is template.HTML because the message is ours and may carry
// markup -- a sentence that emphasises the address a code went to should not
// have to be three template fragments in English clause order. Anything
// substituted in is data and is escaped on the way; see subst.
func (p *Printer) T(key string, data ...any) template.HTML {
	return p.render(key, p.form(key, "other"), nil, data...)
}

// N renders a message that counts something.
//
// The form is chosen by CLDR for this language, so a caller never decides
// between singular and plural -- which is what stops "1 application(s)" and
// what makes six-form languages work without every call site knowing they
// exist. The count is available to the message as {n}.
func (p *Printer) N(key string, n int, data ...any) template.HTML {
	text := p.form(key, formName[cardinalForm(p, n)])
	return p.render(key, text, map[string]string{"n": strconv.Itoa(n)}, data...)
}

// cardinalForm is the CLDR category for this count in this language.
//
// Split out so a test can assert the CATEGORY -- "Russian puts 21 with 1" --
// without a translation having to exist to observe it. N calls this, so the
// test exercises the path the pages use rather than a parallel one.
func cardinalForm(p *Printer, n int) plural.Form {
	return plural.Cardinal.MatchPlural(p.tag, n, 0, 0, 0, 0)
}

// mustTag parses a language tag, falling back to English.
//
// language.Make never fails -- it returns Und for nonsense -- which is what is
// wanted here: an unrecognised tag should render English, not panic on a page
// somebody is trying to sign in through.
func mustTag(lang string) language.Tag { return language.Make(lang) }

var formName = map[plural.Form]string{
	plural.Other: "other", plural.Zero: "zero", plural.One: "one",
	plural.Two: "two", plural.Few: "few", plural.Many: "many",
}

// form finds a message's text, falling back category by category and then
// language by language.
//
// A translation that omits "few" is more useful with its "other" text than with
// nothing, and a translation missing a key entirely is more useful in English
// than as a raw key -- a person can act on an English sentence.
func (p *Printer) form(key, want string) string {
	if p.b == nil {
		return key
	}
	for _, lang := range []string{p.lang, Default} {
		e, ok := p.b.msgs[lang][key]
		if !ok {
			continue
		}
		if s, ok := e.forms[want]; ok {
			return s
		}
		if s, ok := e.forms["other"]; ok {
			return s
		}
	}
	// Deliberately the key. A blank would be a page with a hole in it that looks
	// finished; the key is visibly wrong and says exactly what is missing.
	return key
}

// render substitutes {name} placeholders, escaping every value.
func (p *Printer) render(key, text string, extra map[string]string, data ...any) template.HTML {
	if !strings.ContainsRune(text, '{') {
		return template.HTML(text)
	}

	lookup := func(name string) (string, bool) {
		if v, ok := extra[name]; ok {
			return v, true
		}
		for _, d := range data {
			if v, ok := field(d, name); ok {
				return stringify(v), true
			}
		}
		return "", false
	}

	var out strings.Builder
	for {
		i := strings.IndexRune(text, '{')
		if i < 0 {
			out.WriteString(text)
			break
		}
		j := strings.IndexRune(text[i:], '}')
		if j < 0 {
			out.WriteString(text)
			break
		}
		out.WriteString(text[:i])
		name := text[i+1 : i+j]
		if v, ok := lookup(name); ok {
			// A message may legitimately contain a link -- "open {this link} on
			// the device with your authenticator app" is one sentence in every
			// language and three fragments if the anchor is pulled out into the
			// template. But returning template.HTML skips the URL sanitising
			// html/template would normally do inside an href, so it is done
			// here instead. Without this, a message that interpolates a URL is
			// a javascript: URI away from being a scripting hole.
			sofar := out.String()
			if inURLAttribute(sofar) {
				v = safeURL(v)
			}
			// The whole safety argument: the message is trusted, the value is
			// not, and the value is escaped here rather than at the call site
			// where somebody would eventually forget.
			escaped := template.HTMLEscapeString(v)
			if !inTag(sofar) {
				escaped = isolate(escaped)
			}
			out.WriteString(escaped)
		} else {
			// Left visible rather than blanked, for the same reason a missing
			// key renders as the key.
			out.WriteString("{" + name + "}")
		}
		text = text[i+j+1:]
	}
	return template.HTML(out.String())
}

// Unicode bidirectional isolates. U+2068 FIRST STRONG ISOLATE opens a run whose
// direction is decided by its own first strong character; U+2069 POP
// DIRECTIONAL ISOLATE closes it.
const (
	firstStrongIsolate = "⁨"
	popDirectional     = "⁩"
)

// isolate stops a value from being re-ordered by the text around it.
//
// The bug this fixes is specific and was found by looking at a rendered Arabic
// page rather than by reading anything. A masked phone number, +44 7700 •••912,
// sits in a right-to-left sentence. The digits are weak left-to-right and the
// bullets are neutral, so the bidirectional algorithm resolves the neutrals to
// the paragraph's direction and displays it as +44 7700 912•••.
//
// Nothing is corrupted -- the value is intact and copies correctly -- but the
// page shows the visible digits at the wrong end of the number. On a screen
// whose entire purpose is letting somebody check WHICH number a code went to,
// that is a person confirming the wrong thing.
//
// Applied to every substituted value, not only in right-to-left languages: the
// data decides the direction, not the page. An Arabic name in an English
// sentence has the same problem in reverse.
func isolate(s string) string {
	if s == "" {
		return s
	}
	return firstStrongIsolate + s + popDirectional
}

// inTag reports whether what has been written so far ends inside a tag.
//
// Isolates are ordinary characters, so they belong in text and not in an
// attribute value, where they would end up inside a URL or an id.
func inTag(sofar string) bool {
	lt := strings.LastIndexByte(sofar, '<')
	if lt < 0 {
		return false
	}
	return strings.LastIndexByte(sofar, '>') < lt
}

// inURLAttribute reports whether what has been written so far ends inside the
// value of an href, src, action or formaction attribute.
//
// Textual rather than a real parse, and that is a deliberate limit: it is
// looking at OUR message text, which is a short sentence, not at arbitrary
// documents. It errs toward saying yes -- treating something as a URL that is
// not costs a sanitising pass on a string that did not need it, while the
// reverse costs a scripting hole.
func inURLAttribute(sofar string) bool {
	// The last unclosed quote, if any, is the attribute being written.
	q := strings.LastIndexAny(sofar, `"'`)
	if q < 0 {
		return false
	}
	// An even number of quotes after it would mean that one was closed.
	if strings.ContainsAny(sofar[q+1:], `"'`) {
		return false
	}
	prefix := strings.ToLower(strings.TrimRight(sofar[:q], " ="))
	for _, attr := range []string{"href", "src", "action", "formaction", "cite"} {
		if strings.HasSuffix(prefix, attr) {
			return true
		}
	}
	return false
}

// safeURL blanks a URL whose scheme can execute.
//
// Relative URLs and the ordinary schemes pass. Anything else -- javascript:,
// data:, vbscript: -- becomes "#", which is visibly inert rather than silently
// dropped, so a page that hits this looks broken to whoever configured it
// instead of working for an attacker.
func safeURL(v string) string {
	// Control characters and whitespace are stripped first: "java\tscript:" is
	// a URL some browsers still run.
	clean := strings.Map(func(r rune) rune {
		if r <= 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)

	i := strings.IndexByte(clean, ':')
	if i < 0 {
		return v // Relative. No scheme to be dangerous.
	}
	// A colon after a slash or a question mark is part of a path or query, not
	// a scheme: "/a:b" is relative.
	if j := strings.IndexAny(clean, "/?#"); j >= 0 && j < i {
		return v
	}
	switch strings.ToLower(clean[:i]) {
	case "http", "https", "mailto", "tel", "otpauth":
		return v
	}
	return "#"
}

// field reads a named map key or struct field from whatever a template passed.
//
// Reflection because `{{T "login.continuewith" .}}` should work for the page's
// data map AND for the element of a {{range}} -- which is a struct in some
// handlers and a map in others. Requiring the caller to know which would put
// the difference into 200 templates.
func field(v any, name string) (any, bool) {
	if v == nil {
		return nil, false
	}
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil, false
		}
		rv = rv.Elem()
	}

	switch rv.Kind() {
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return nil, false
		}
		got := rv.MapIndex(reflect.ValueOf(name).Convert(rv.Type().Key()))
		if !got.IsValid() {
			return nil, false
		}
		return got.Interface(), true
	case reflect.Struct:
		got := rv.FieldByName(name)
		// CanInterface excludes unexported fields, which reflect would panic on.
		if !got.IsValid() || !got.CanInterface() {
			return nil, false
		}
		return got.Interface(), true
	}
	return nil, false
}

func stringify(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case template.HTML:
		// Deliberately treated as text. A caller that has already decided
		// something is safe HTML does not get to smuggle it through a message
		// argument, because the message may be an operator's.
		return string(s)
	case int:
		return strconv.Itoa(s)
	case int64:
		return strconv.FormatInt(s, 10)
	case bool:
		return strconv.FormatBool(s)
	case nil:
		return ""
	}
	return ""
}

// Keys lists every message key the default catalogue defines, sorted.
func (b *Bundle) Keys() []string {
	if b == nil {
		return nil
	}
	out := make([]string, 0, len(b.msgs[Default]))
	for k := range b.msgs[Default] {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Missing lists keys the default catalogue has and this language does not.
func (b *Bundle) Missing(lang string) []string {
	if b == nil {
		return nil
	}
	var out []string
	for k := range b.msgs[Default] {
		if _, ok := b.msgs[lang][k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
