package docsync

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// No disabled guard may be committed.
//
// This exists because one was. `internal/clientauth/privatekeyjwt.go` carried:
//
//	if false && (payload == nil) {
//	    return nil, fmt.Errorf("the client assertion was not signed by any registered key: %w", lastErr)
//	}
//
// That is a mutation-testing edit. The harness rewrites a guard as
// `if false && (<original condition>)` rather than deleting it, so the variables
// stay referenced and the package still compiles — which is exactly what makes it
// survive review: it compiles, it is one token long, and it reads almost like the
// original.
//
// It reached main in commit c3c6748, alongside unrelated test work, and disabled
// the check that refuses a client assertion no registered key verified.
//
// It was not exploitable: with the guard dead, `payload` stayed nil and
// `json.Unmarshal(nil, &c)` failed, so the assertion was refused anyway. The
// property held by accident, through a JSON parse error, rather than through the
// check written to enforce it.
//
// A grep is a blunt instrument and this is the right place for one. The pattern
// has no legitimate use in this codebase: `if false` is dead code a compiler will
// not warn about, and every instance found so far came from a mutation run.
func TestNoDisabledGuardsWereCommitted(t *testing.T) {
	root := repoRoot(t)

	// `if false`, `&& false`, `|| true` — the three shapes a mutation harness
	// leaves behind when it neutralises a condition without deleting it.
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`\bif\s+false\b`),
		regexp.MustCompile(`&&\s+false\b`),
		regexp.MustCompile(`\|\|\s+true\b`),
	}

	var found []string
	var scanned int
	err := filepath.Walk(filepath.Join(root, "engine"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		// Test files are exempt: a test may legitimately write `if false` to
		// document a case, and this file itself contains the patterns verbatim.
		if strings.HasSuffix(p, "_test.go") {
			return nil
		}
		scanned++
		src := readSource(t, p)
		for _, line := range strings.Split(src, "\n") {
			code := line
			if i := strings.Index(code, "//"); i >= 0 {
				code = code[:i] // a comment quoting the pattern is not the pattern
			}
			for _, re := range patterns {
				if re.MatchString(code) {
					rel, _ := filepath.Rel(root, p)
					found = append(found, rel+": "+strings.TrimSpace(line))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 50 {
		t.Fatalf("only %d non-test Go files scanned; the walk is wrong and this "+
			"test would pass by finding nothing", scanned)
	}
	if len(found) > 0 {
		t.Errorf("%d disabled condition(s) in committed source:\n  %s\n\n"+
			"`if false && (<cond>)` is what a mutation harness leaves behind when it "+
			"neutralises a guard without deleting it — it compiles, so nothing else "+
			"catches it. One of these reached main and disabled the check that "+
			"refuses a client assertion no registered key had verified.",
			len(found), strings.Join(found, "\n  "))
	}
}
