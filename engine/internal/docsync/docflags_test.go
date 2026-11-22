package docsync

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every flag a page tells somebody to pass to `signari` is one the CLI defines.
//
// TestEveryDocumentedCommandExists checks the command words and stops there.
// docs/dpop.md showed `signari client set-dpop -client payments` from the day it
// was written, and the flag is -client-id: the command it documented failed
// with "flag provided but not defined", and so did the opt-out command this
// repository printed after an import. The command was right and the line was
// still wrong, which is the half nothing read.
// cliFlags is every flag name cmd/signari defines.
func cliFlags(t *testing.T, root string) map[string]bool {
	t.Helper()
	defined := map[string]bool{"h": true, "help": true}
	define := regexp.MustCompile(`\.(?:String|Bool|Int|Int64|Uint|Uint64|Float64|Duration|Var|Func|BoolFunc|TextVar)\(\s*(?:&?\w+,\s*)?"([a-z][a-z0-9-]*)"`)
	cmdDir := filepath.Join(root, "engine", "cmd", "signari")
	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		for _, m := range define.FindAllStringSubmatch(readRaw(t, filepath.Join(cmdDir, e.Name())), -1) {
			defined[m[1]] = true
		}
	}
	if len(defined) < 50 {
		t.Fatalf("only %d flags were parsed out of cmd/signari, so the definition "+
			"pattern has stopped matching", len(defined))
	}
	return defined
}

func TestEveryDocumentedFlagExists(t *testing.T) {
	root := repoRoot(t)
	defined := cliFlags(t, root)

	// An invocation: `signari` and a command word, up to the end of the line or
	// a closing backtick, with shell continuations joined first. The tail stops
	// at the next shell operator, so `signari verify && date -u` does not lend
	// date's flag to signari, and a $(...) substitution is dropped, so the -c in
	// `-secret "$(head -c 24 /dev/urandom)"` is head's.
	invocation := regexp.MustCompile("(?m)\\bsignari ([a-z][a-z0-9-]*(?: [a-z][a-z0-9-]*)?)([^`\\n]*)")
	operator := regexp.MustCompile(`&&|\|\||[|;>]`)
	substitution := regexp.MustCompile(`\$\([^)]*\)`)
	flag := regexp.MustCompile(`(?:^|\s)--?([a-z][a-z0-9-]*)`)

	var undefined []string
	seen := 0
	err := filepath.Walk(filepath.Join(root, "docs"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".md") {
			return err
		}
		body := strings.ReplaceAll(readRaw(t, path), "\\\n", " ")
		rel, _ := filepath.Rel(root, path)
		for _, m := range invocation.FindAllStringSubmatch(body, -1) {
			tail := substitution.ReplaceAllString(m[2], "")
			if loc := operator.FindStringIndex(tail); loc != nil {
				tail = tail[:loc[0]]
			}
			for _, f := range flag.FindAllStringSubmatch(tail, -1) {
				seen++
				if !defined[f[1]] {
					undefined = append(undefined, rel+": signari "+m[1]+" -"+f[1])
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 100 {
		t.Fatalf("only %d documented flags were found, so this test is reading the "+
			"documentation wrong", seen)
	}
	if len(undefined) > 0 {
		sort.Strings(undefined)
		t.Errorf("%d documented invocation(s) pass a flag the CLI does not define:\n  %s\n\n"+
			"Each fails with \"flag provided but not defined\". Correct the page, or "+
			"define the flag.", len(undefined), strings.Join(undefined, "\n  "))
	}
}
