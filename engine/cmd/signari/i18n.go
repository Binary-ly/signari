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

	incomplete := 0
	for _, lang := range b.Languages() {
		if lang == i18n.Default {
			continue
		}
		missing := b.Missing(lang)
		if len(missing) == 0 {
			fmt.Printf("OK       %s\n", lang)
			continue
		}
		incomplete++
		fmt.Printf("PARTIAL  %s -- %d message(s) fall back to %s:\n",
			lang, len(missing), i18n.Default)
		for _, key := range missing {
			fmt.Printf("           %s\n", key)
		}
	}

	if incomplete > 0 {
		return fmt.Errorf("%d language(s) are incomplete; anybody whose browser "+
			"asks for one gets a sign-in page in two languages at once", incomplete)
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
