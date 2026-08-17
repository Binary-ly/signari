package docsync

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every two-word command's group must be registered for dispatch.
//
// main.go joins two argv words into one command only when the first is in
// `twoWordCommands`. Miss the entry and the command prints the usage text
// instead of running, with nothing indicating that the dispatch is what is
// wrong -- it looks exactly like a typo.
//
// The set's own comment records that this already happened once, with
// `scim-source`. It then happened again with `events`, which is what prompted
// this test: a comment saying "remember to add it here" is not a mechanism.
func TestEveryTwoWordCommandGroupIsRegistered(t *testing.T) {
	root := repoRoot(t)
	src := readSource(t, filepath.Join(root, "engine", "cmd", "signari", "main.go"))

	// The registered groups.
	block := regexp.MustCompile(`var twoWordCommands = map\[string\]bool\{([^}]*)\}`).
		FindStringSubmatch(src)
	if block == nil {
		t.Fatal("twoWordCommands was not found; this test is reading main.go wrong")
	}
	registered := map[string]bool{}
	for _, m := range regexp.MustCompile(`"([a-z][a-z0-9-]*)"\s*:`).
		FindAllStringSubmatch(block[1], -1) {
		registered[m[1]] = true
	}
	if len(registered) < 10 {
		t.Fatalf("only %d groups parsed out of twoWordCommands; reading it wrong",
			len(registered))
	}

	// Every two-word command the switch dispatches.
	var missing []string
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`case\s+"([a-z][a-z0-9-]*)\s+([a-z][a-z0-9-]*)":`).
		FindAllStringSubmatch(src, -1) {
		group := m[1]
		if registered[group] || seen[group] {
			continue
		}
		seen[group] = true
		missing = append(missing, group+" (e.g. `"+group+" "+m[2]+"`)")
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d command group(s) are dispatched with two words but absent from "+
			"twoWordCommands, so they print the usage text instead of running:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// A case label with three words can never be reached.
//
// Dispatch joins at most TWO argv words into a command, so `case "authz model
// set":` is dead code -- the binary reports "no command given" and the switch
// arm is never entered. It compiles, and every test that does not invoke the
// CLI passes.
//
// Found by writing `authz model set` and watching a correctly-built binary
// refuse to run it.
func TestNoCommandNeedsMoreThanTwoWords(t *testing.T) {
	root := repoRoot(t)
	src := readSource(t, filepath.Join(root, "engine", "cmd", "signari", "main.go"))

	var unreachable []string
	for _, m := range regexp.MustCompile(`case\s+"([a-z][a-z0-9 -]*)":`).
		FindAllStringSubmatch(src, -1) {
		if len(strings.Fields(m[1])) > 2 {
			unreachable = append(unreachable, m[1])
		}
	}
	sort.Strings(unreachable)
	if len(unreachable) > 0 {
		t.Errorf("%d case label(s) have more than two words, so dispatch can never "+
			"reach them and the command reports \"no command given\":\n  %s",
			len(unreachable), strings.Join(unreachable, "\n  "))
	}
}
