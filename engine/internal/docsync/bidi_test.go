package docsync

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoSourceFileHoldsABidirectionalControl fails when a Go file in any module here holds
// one of the characters that reorder the text around them (U+202A-U+202E, U+2066-U+2069).
//
// A file holding one reads one way in an editor and a review and compiles another way, the
// failure class CVE-2021-42574 named "Trojan Source". It reached a test file here once,
// written as an escape and stored as the character itself, in the test of the very code
// that strips these from a client's name. Built from its code point, as
// store/clientnames_test.go now does, the character is in the string and not the file.
func TestNoSourceFileHoldsABidirectionalControl(t *testing.T) {
	root := repoRoot(t)
	checked := 0
	for _, module := range []string{"engine", "terraform-provider-signari", "operator", "sdk", "tools"} {
		err := filepath.WalkDir(filepath.Join(root, module), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "node_modules" || d.Name() == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".ts") {
				return nil
			}
			checked++
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)
			for line := 1; scanner.Scan(); line++ {
				for _, r := range scanner.Text() {
					if (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
						rel, _ := filepath.Rel(root, path)
						t.Errorf("%s:%d holds U+%04X, which reorders the text around it: build it from "+
							"its code point, string(rune(0x%04x)), so the file reads as it compiles", rel, line, r, r)
					}
				}
			}
			return scanner.Err()
		})
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if checked < 100 {
		t.Fatalf("only %d source files found; the walk, not the tree, is wrong", checked)
	}
}
