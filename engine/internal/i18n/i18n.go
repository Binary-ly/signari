// Package i18n is the message catalogue behind every page a person sees.
//
// The pages were English sentences written into templates. Changing "Sign in"
// meant editing a template; there was no way to say it in another language at
// all, and no way for an operator to reword it without forking the page.
//
// # Why not one string per language in the template
//
// Because word order is not a property of English. "Signing you out of 3
// applications" is one sentence here and a different arrangement in Japanese,
// and a template that interleaves markup with English clause order cannot
// express the second. Messages are whole sentences, keyed, and the template
// asks for a key.
//
// # Plurals are not two forms
//
// English has two. Arabic has six, and Russian puts 21 in the SAME form as 1
// while putting 5 in another. Any scheme with an `if n == 1` in it is wrong for
// most of the languages it claims to support -- and wrong invisibly, because
// the page still renders. Form selection is delegated to CLDR through
// golang.org/x/text, which was already a dependency.
//
// # What is trusted and what is not
//
// A message is OURS -- it ships in this binary or comes from an operator's
// catalogue -- so it may contain markup, and T returns template.HTML.
// Everything substituted INTO a message is data, and is HTML-escaped first.
// That split is the whole safety argument, and TestAnArgumentCannotInjectMarkup
// is what holds it.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/text/language"
)

//go:embed locales/*.json
var builtin embed.FS

// Default is the language every other one falls back to, key by key.
//
// It is also the only catalogue guaranteed complete: a page whose Japanese
// translation is missing one string renders that string in English rather than
// rendering a key, because a person can act on an English sentence and cannot
// act on `consent.scopes.heading`.
const Default = "en"

// entry is one message: a plain string, or one string per CLDR plural form.
//
// Both spellings are accepted in the JSON because most messages have no number
// in them, and making every one of those an object with a single "other" would
// be noise a translator has to read past on every line.
type entry struct {
	// forms is keyed by CLDR plural category. A message with no plural has its
	// text under "other", which is the category every language always has.
	forms map[string]string
}

func (e *entry) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		e.forms = map[string]string{"other": s}
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("a message must be a string or an object of plural "+
			"forms, and this is neither: %s", strings.TrimSpace(string(b)))
	}
	if len(m) == 0 {
		return fmt.Errorf("a message with no forms in it says nothing")
	}
	for form := range m {
		if !validForm[form] {
			return fmt.Errorf("%q is not a CLDR plural category; the categories "+
				"are zero, one, two, few, many and other", form)
		}
	}
	if _, ok := m["other"]; !ok {
		// Every language has "other". A message without it has a hole that only
		// appears at a particular number, in a particular language.
		return fmt.Errorf("a plural message must define \"other\", which is the " +
			"one category every language has")
	}
	e.forms = m
	return nil
}

var validForm = map[string]bool{
	"zero": true, "one": true, "two": true,
	"few": true, "many": true, "other": true,
}

// Bundle is every catalogue that was loaded, and the matcher over them.
type Bundle struct {
	msgs    map[string]map[string]*entry // language -> key -> message
	tags    []language.Tag
	names   []string // parallel to tags, as written
	matcher language.Matcher
}

// Load reads the built-in catalogues, then merges an operator's over them.
//
// An operator directory is a THEME directory's locales/ subdirectory, and it is
// merged key by key rather than replacing a file. Rewording one sentence should
// be a three-line file, not a fork of the whole catalogue that stops receiving
// new strings the day it is written.
//
// Problems with an operator's file are returned rather than fatal, for the same
// reason a refused page override is: a typo in a JSON file at four in the
// afternoon must not stop everybody signing in.
func Load(overrideDir string) (*Bundle, []error, error) {
	b := &Bundle{msgs: map[string]map[string]*entry{}}

	entries, err := fs.ReadDir(builtin, "locales")
	if err != nil {
		return nil, nil, fmt.Errorf("reading the built-in catalogues: %w", err)
	}
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".json")
		raw, err := builtin.ReadFile("locales/" + e.Name())
		if err != nil {
			return nil, nil, err
		}
		msgs, err := parse(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("the built-in %s catalogue: %w", name, err)
		}
		b.msgs[name] = msgs
	}
	if _, ok := b.msgs[Default]; !ok {
		return nil, nil, fmt.Errorf("there is no %s catalogue, so nothing has a "+
			"fallback", Default)
	}

	var problems []error
	if overrideDir != "" {
		problems = b.mergeOverrides(overrideDir)
	}

	b.index()
	return b, problems, nil
}

// mergeOverrides layers an operator's catalogues on top of the built-in ones.
func (b *Bundle) mergeOverrides(dir string) []error {
	var problems []error

	found, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Having no locales/ directory is the normal case.
		}
		return []error{fmt.Errorf("reading %s: %w", dir, err)}
	}

	for _, e := range found {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		path := filepath.Join(dir, e.Name())

		if _, err := language.Parse(name); err != nil {
			problems = append(problems, fmt.Errorf(
				"%s: %q is not a language tag, so this file was ignored; name it "+
					"like en.json, fr.json or pt-BR.json", path, name))
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", path, err))
			continue
		}
		msgs, err := parse(raw)
		if err != nil {
			problems = append(problems, fmt.Errorf(
				"%s: the file was refused and the built-in messages are being used "+
					"instead: %w", path, err))
			continue
		}

		// A key nobody renders is almost always a typo in the key rather than a
		// message we forgot, and silently keeping it means the operator believes
		// they changed something they did not.
		for key := range msgs {
			if _, known := b.msgs[Default][key]; !known {
				problems = append(problems, fmt.Errorf(
					"%s: %q is not a message this server renders, so it was ignored; "+
						"`signari i18n keys` prints every key", path, key))
				delete(msgs, key)
			}
		}

		if b.msgs[name] == nil {
			b.msgs[name] = map[string]*entry{}
		}
		for key, m := range msgs {
			b.msgs[name][key] = m
		}
	}
	return problems
}

// index builds the matcher, with the default language first.
//
// First is load-bearing: x/text returns index 0 when nothing matches, so the
// tag in that position is what a request for a language we do not have will
// get. Sorting the rest keeps `signari i18n list` stable.
func (b *Bundle) index() {
	rest := make([]string, 0, len(b.msgs))
	for name := range b.msgs {
		if name != Default {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)

	b.names = append([]string{Default}, rest...)
	b.tags = make([]language.Tag, 0, len(b.names))
	for _, name := range b.names {
		b.tags = append(b.tags, language.Make(name))
	}
	b.matcher = language.NewMatcher(b.tags)
}

func parse(raw []byte) (map[string]*entry, error) {
	var out map[string]*entry
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// Languages lists what was loaded, default first.
//
// This is what discovery advertises as ui_locales_supported, which is why it
// reports what is actually present rather than a list somebody maintains.
func (b *Bundle) Languages() []string {
	if b == nil {
		return []string{Default}
	}
	return append([]string(nil), b.names...)
}

// Has reports whether a language was loaded.
func (b *Bundle) Has(lang string) bool {
	if b == nil {
		return lang == Default
	}
	_, ok := b.msgs[lang]
	return ok
}

// HasKey reports whether the default catalogue defines a message.
//
// The DEFAULT catalogue specifically: it is the one every other language falls
// back to, so a key it does not have is a key no language can render.
func (b *Bundle) HasKey(key string) bool {
	if b == nil {
		return false
	}
	_, ok := b.msgs[Default][key]
	return ok
}
