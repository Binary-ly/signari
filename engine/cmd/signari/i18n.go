package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"signari.dev/engine/internal/i18n"
	"signari.dev/engine/internal/pages"
)

// `signari i18n ...` -- the operator's side of internal/i18n.
//
//	i18n list     what languages this deployment can render
//	i18n status   which of them are complete, and what is missing
//	i18n keys     every message key, for writing a catalogue against
//
// Reads files and nothing else, so it works in a pipeline with no database --
// the same reason `theme check` is dispatched before a DSN is required.

// i18nList prints the languages that would be advertised as ui_locales_supported.
func i18nList(dir string) error {
	b, problems, err := loadCatalogues(dir)
	if err != nil {
		return err
	}
	reportCatalogueProblems(problems)

	for _, lang := range b.Languages() {
		missing := len(b.Missing(lang))
		switch {
		case lang == i18n.Default:
			fmt.Printf("%-8s %s\n", lang, "the reference; everything falls back to it")
		case missing == 0:
			fmt.Printf("%-8s %s\n", lang, "complete")
		default:
			fmt.Printf("%-8s %d message(s) missing\n", lang, missing)
		}
	}
	return nil
}

// i18nStatus names what each language is missing.
//
// Exits non-zero when anything is incomplete, so a pipeline can refuse to ship
// a half-translated language. That is the point of having it: the failure mode
// is a page that renders in two languages at once, which nothing downstream
// will catch and nobody will report as a bug.
func i18nStatus(dir string) error {
	b, problems, err := loadCatalogues(dir)
	if err != nil {
		return err
	}
	reportCatalogueProblems(problems)

	// Three checks, not one. Reporting only missing keys passes a catalogue whose
	// key was RENAMED (the translation keeps the old name, so it looks finished
	// while the new key falls back), and passes one whose translation dropped a
	// substitution (the sentence reads naturally and has a hole where a value
	// belongs). Both are invisible to a count.
	incomplete, stale, broken := 0, 0, 0
	for _, lang := range b.Languages() {
		if lang == i18n.Default {
			continue
		}
		missing := b.Missing(lang)
		extra := b.Extra(lang)
		mismatched := b.PlaceholderMismatches(lang)

		if len(missing) == 0 && len(extra) == 0 && len(mismatched) == 0 {
			fmt.Printf("OK       %s\n", lang)
			continue
		}
		if len(missing) > 0 {
			incomplete++
			fmt.Printf("PARTIAL  %s -- %d message(s) fall back to %s:\n",
				lang, len(missing), i18n.Default)
			for _, key := range missing {
				fmt.Printf("           %s\n", key)
			}
		}
		if len(extra) > 0 {
			stale++
			fmt.Printf("STALE    %s -- %d message(s) translate a key %s no longer has.\n"+
				"           Usually the key was renamed and this file kept the old name,\n"+
				"           which means the NEW key is untranslated:\n",
				lang, len(extra), i18n.Default)
			for _, key := range extra {
				fmt.Printf("           %s\n", key)
			}
		}
		if len(mismatched) > 0 {
			broken++
			fmt.Printf("SUBST    %s -- %d message(s) do not carry the same substitutions:\n",
				lang, len(mismatched))
			for _, m := range mismatched {
				if len(m.Dropped) > 0 {
					fmt.Printf("           %s drops %s (the value never appears)\n",
						m.Key, strings.Join(m.Dropped, ", "))
				}
				if len(m.Added) > 0 {
					fmt.Printf("           %s adds %s (renders literally on screen)\n",
						m.Key, strings.Join(m.Added, ", "))
				}
			}
		}
	}

	if incomplete > 0 {
		return fmt.Errorf("%d language(s) are incomplete; anybody whose browser "+
			"asks for one gets a sign-in page in two languages at once", incomplete)
	}
	if stale > 0 {
		return fmt.Errorf("%d language(s) carry messages for keys that no longer "+
			"exist, so they look more complete than they are", stale)
	}
	if broken > 0 {
		return fmt.Errorf("%d language(s) have messages whose substitutions do not "+
			"match; each one renders a sentence with a hole in it, or a literal "+
			"placeholder, in that language only", broken)
	}
	if len(problems) > 0 {
		return fmt.Errorf("%d catalogue file(s) were refused", len(problems))
	}
	return nil
}

// i18nKeys prints every message key, sorted.
//
// What somebody writing a translation needs: the list to work against, and the
// list an override file is checked against.
func i18nKeys(dir string) error {
	b, problems, err := loadCatalogues(dir)
	if err != nil {
		return err
	}
	reportCatalogueProblems(problems)

	keys := b.Keys()
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Println(k)
	}
	return nil
}

// loadCatalogues reads the built-in catalogues and any an operator has added.
//
// Through pages.Load rather than i18n.Load directly, so the CLI and the running
// server resolve a theme directory the same way -- including the locales/
// subdirectory, which is the part somebody would otherwise get wrong once and
// then not understand why nothing changed.
func loadCatalogues(dir string) (*i18n.Bundle, []error, error) {
	if dir == "" {
		dir = os.Getenv("SIGNARI_THEME_DIR")
	}
	set, problems, err := pages.Load(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("loading pages and catalogues: %w", err)
	}
	return set.Bundle(), problems, nil
}

// reportCatalogueProblems prints refusals to stderr.
//
// Only the ones about messages: pages.Load reports refused PAGES too, and
// repeating those under an i18n command sends somebody to the wrong file.
func reportCatalogueProblems(problems []error) {
	for _, p := range problems {
		if strings.Contains(p.Error(), ".json") {
			fmt.Fprintln(os.Stderr, "REFUSED  "+p.Error())
		}
	}
}
