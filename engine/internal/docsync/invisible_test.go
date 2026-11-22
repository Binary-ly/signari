package docsync

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// No tracked text file may carry an invisible formatting character as a raw
// byte sequence.
//
// # The failure this guards against
//
// Bidirectional controls (U+202A–U+202E, U+2066–U+2069) reorder how source is
// displayed without changing how it is compiled, so code a reviewer reads is not
// the code that runs — the "Trojan Source" class, CWE-1007. Zero-width and other
// format characters (U+200B, U+00AD, U+FFF9…) and the Unicode line and paragraph
// separators do the quieter version: an identifier or a string that looks like
// another one.
//
// This repository had them for good reasons — the i18n printer's isolate
// characters, and test inputs proving the CIBA binding message refuses exactly
// these characters — and every one was a literal byte. gosec flagged the
// printer's. A reviewer could not see any of them.
//
// Go, JSON, YAML and HTML all have an escape that says what the character is
// (`\U00002068` in Go, `&#x2068;` in HTML). Writing it that way costs nothing and
// makes the character visible to the person approving the change. (Some editing
// tools decode a lowercase `\u` escape back into the raw character as they write
// the file; the eight-digit form survives them, and this test catches the rest.)
func TestNoInvisibleFormattingCharacterIsWrittenRaw(t *testing.T) {
	root := repoRoot(t)
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("cannot ask git what is tracked: %v", err)
	}

	scanned := 0
	var found []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f == "" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil || !utf8.Valid(body) || strings.IndexByte(string(body), 0) >= 0 {
			continue // binary, or removed from the working tree
		}
		scanned++
		line := 1
		for i, r := range string(body) {
			if r == '\n' {
				line++
				continue
			}
			if r == '\U0000FEFF' && i == 0 {
				continue // a byte-order mark at the very start is an encoding marker
			}
			if unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
				found = append(found, fmt.Sprintf("%s:%d: raw U+%04X — write it as an escape", f, line, r))
			}
		}
	}

	if scanned < 500 {
		t.Fatalf("only %d tracked text files scanned; the walk is not finding the tree "+
			"and this test would pass over everything", scanned)
	}
	for _, f := range found {
		t.Error(f)
	}
}
