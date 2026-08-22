package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"signari.dev/engine/internal/pages"
)

// `signari theme ...` -- the operator's side of internal/pages.
//
// Two commands, and the split matters:
//
//	theme check   validate a directory, exit non-zero if anything is wrong
//	theme eject   write the built-in pages out so there is something to edit
//
// `check` exists because the server does NOT stop for a broken theme. It refuses
// the page, logs, and serves the built-in -- which is the right behaviour at four
// in the afternoon and the wrong behaviour in a pipeline, where a deployment that
// quietly ignores the theme you just wrote is a deployment that ships the wrong
// thing. This is where stopping is correct.

// themeCheck validates a theme directory.
func themeCheck(dir string) error {
	if dir == "" {
		dir = os.Getenv("SIGNARI_THEME_DIR")
	}
	if dir == "" {
		return fmt.Errorf("give -theme-dir, or set SIGNARI_THEME_DIR")
	}

	ok, problems := pages.Check(dir)

	for _, name := range ok {
		fmt.Printf("  ok       %s.html\n", name)
	}
	for _, p := range problems {
		fmt.Printf("  REFUSED  %s\n", p)
	}
	fmt.Println()

	if len(problems) > 0 {
		// Non-zero, and say what non-zero means here. A theme that fails this and
		// is deployed anyway does not break the server -- it is silently ignored,
		// which is the outcome somebody spends an afternoon on.
		return fmt.Errorf("%d of %d file(s) would be refused. The server would "+
			"NOT fail to start: it would serve the built-in page instead and log a "+
			"warning, so a deployment carrying this theme would quietly not have it",
			len(problems), len(ok)+len(problems))
	}
	fmt.Printf("%d file(s) accepted. Set SIGNARI_THEME_DIR=%s and restart.\n",
		len(ok), dir)
	return nil
}

// themeEject writes the built-in pages to a directory to start editing from.
//
// Copying what ships rather than generating a skeleton: a theme that starts as
// the real page is one where the first edit is a small one, and where every
// hidden field the validator will later ask for is already present. A skeleton
// would have the operator reconstruct those from documentation, which is how a
// CSRF token goes missing.
func themeEject(dir string, only string, force bool) error {
	if dir == "" {
		return fmt.Errorf("give -theme-dir: the directory to write the pages into")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	src := pages.BuiltIn()
	names := make([]string, 0, len(src))
	for n := range src {
		if only != "" && n != only {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return fmt.Errorf("no page is named %q; run `signari theme check` against "+
			"an empty directory to see the list", only)
	}

	var wrote, skipped int
	for _, n := range names {
		path := filepath.Join(dir, n+".html")
		if _, err := os.Stat(path); err == nil && !force {
			// Never silently. An operator ejecting twice would otherwise lose the
			// work they did between the two.
			fmt.Printf("  skipped  %s.html (already exists; -force to overwrite)\n", n)
			skipped++
			continue
		}
		if err := os.WriteFile(path, []byte(src[n]), 0o644); err != nil {
			return err
		}
		wrote++
	}
	fmt.Printf("\nwrote %d file(s) to %s", wrote, dir)
	if skipped > 0 {
		fmt.Printf(", skipped %d", skipped)
	}
	fmt.Println(".")
	fmt.Println("\nDelete every file you do not intend to change. A file left here " +
		"is a copy that stops receiving upstream fixes -- including security fixes " +
		"to the page it replaces.")
	fmt.Println("\nThe usual starting point is layout.html alone: it carries the " +
		"head, the logo and the footer for every page, and contains no form, so " +
		"there is nothing in it to break.")
	fmt.Printf("\nThen: signari theme check -theme-dir %s\n", dir)
	return nil
}

// themeList shows which page each name refers to, and where it is coming from.
func themeList(dir string) error {
	if dir == "" {
		dir = os.Getenv("SIGNARI_THEME_DIR")
	}
	set, problems, err := pages.Load(dir)
	if err != nil {
		return err
	}
	var overridden int
	for _, n := range set.Names() {
		origin := set.Origin(n)
		if origin == "built-in" {
			fmt.Printf("  %-14s built-in\n", n)
			continue
		}
		overridden++
		fmt.Printf("  %-14s %s\n", n, origin)
	}
	fmt.Printf("\n%d page(s), %d overridden.\n", len(set.Names()), overridden)
	for _, p := range problems {
		fmt.Printf("\nREFUSED: %s\n", p)
	}
	if len(problems) > 0 {
		return fmt.Errorf("%d override(s) were refused", len(problems))
	}
	if dir == "" {
		fmt.Println("\nSIGNARI_THEME_DIR is not set, so nothing can be overridden.")
	}
	return nil
}
