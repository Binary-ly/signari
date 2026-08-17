package docsync

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// No two CLI flags may share a name.
//
// Go's flag package PANICS on a redefined flag, and the flags are all declared
// together before dispatch -- so one duplicate does not break one command, it
// breaks EVERY command, including `migrate up` and `serve`. The binary builds,
// passes every unit test, and then panics on first use.
//
// This happened twice while building the event and authorization commands
// (`-events`, then `-file`). Both times the build was clean and both times the
// binary was completely unusable. Nothing in the test suite invokes the CLI, so
// nothing noticed.
func TestNoTwoFlagsShareAName(t *testing.T) {
	root := repoRoot(t)
	src := readSource(t, filepath.Join(root, "engine", "cmd", "signari", "main.go"))

	// fs.String / fs.Bool / fs.Int / fs.Duration / fs.Int64 / fs.Float64, and
	// the Var forms, all take the name as their first argument.
	re := regexp.MustCompile(`fs\.(?:String|Bool|Int|Int64|Uint|Uint64|Float64|Duration)(?:Var)?\(\s*(?:&\w+\s*,\s*)?"([a-zA-Z][a-zA-Z0-9._-]*)"`)
	matches := re.FindAllStringSubmatch(src, -1)
	if len(matches) < 30 {
		t.Fatalf("only %d flags parsed out of main.go; this test is reading it wrong",
			len(matches))
	}

	seen := map[string]int{}
	for _, m := range matches {
		seen[m[1]]++
	}
	var dupes []string
	for name, n := range seen {
		if n > 1 {
			dupes = append(dupes, name+" (declared "+itoa(n)+" times)")
		}
	}
	sort.Strings(dupes)
	if len(dupes) > 0 {
		t.Fatalf("%d flag name(s) are declared more than once. Go's flag package "+
			"panics on this, and because every flag is declared before dispatch it "+
			"breaks EVERY command, not just the one that added it:\n  %s",
			len(dupes), strings.Join(dupes, "\n  "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
