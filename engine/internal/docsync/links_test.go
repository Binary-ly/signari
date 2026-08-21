package docsync

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every relative link in a shipped document must point at something the reader
// actually receives.
//
// # Why "actually receives" is the whole test
//
// Some documentation in this repository is deliberately not published: internal
// reviews, comparisons and working notes are kept out of the tree through
// .git/info/exclude, which is local and is never committed. Those files still sit
// in the working copy of the machine that wrote them.
//
// So the obvious version of this check -- does the target exist on disk? -- is
// worse than useless, because it passes on exactly the machine where the mistake
// is made and fails for nobody. Written that way it found one broken link. Asking
// git what is tracked instead found nine, of which eight pointed at documents
// that were never going to be published.
//
// A dangling link is a small thing on its own. Nine of them at the top of a
// command reference, pointing at pages the reader cannot obtain, is a page that
// looks like it is hiding something.
var mdLink = regexp.MustCompile(`\[([^\]]*)\]\(([^)#\s]+?)(?:#[^)]*)?\)`)

func TestEveryDocumentLinkResolvesForAReader(t *testing.T) {
	root := repoRoot(t)

	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		// Not a git checkout -- a release tarball, or git is absent. Skipping is
		// right: this test asks a question only git can answer, and a check that
		// silently degrades to the weaker disk-based one would report success
		// while measuring something else.
		t.Skipf("cannot ask git what is tracked: %v", err)
	}
	tracked := map[string]bool{}
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			tracked[filepath.ToSlash(f)] = true
		}
	}
	if len(tracked) == 0 {
		t.Skip("git reported no tracked files")
	}

	var broken []string
	for f := range tracked {
		if !strings.HasSuffix(f, ".md") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, m := range mdLink.FindAllStringSubmatch(string(body), -1) {
			target := m[2]
			switch {
			case strings.HasPrefix(target, "http://"),
				strings.HasPrefix(target, "https://"),
				strings.HasPrefix(target, "mailto:"),
				strings.HasPrefix(target, "tel:"):
				continue
			}
			resolved := filepath.ToSlash(filepath.Clean(
				filepath.Join(filepath.Dir(f), filepath.FromSlash(target))))
			if tracked[resolved] {
				continue
			}
			// Named separately, because "the file is right there" is the first
			// thing the person reading this failure will think.
			hint := ""
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(resolved))); err == nil {
				hint = " (it exists in your working copy but is NOT tracked, " +
					"so nobody who clones this repository gets it)"
			}
			broken = append(broken, f+" -> "+target+hint)
		}
	}
	sort.Strings(broken)
	if len(broken) > 0 {
		t.Errorf("%d link(s) point at something the reader does not get:\n  %s",
			len(broken), strings.Join(broken, "\n  "))
	}
}
