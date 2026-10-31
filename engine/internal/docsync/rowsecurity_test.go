package docsync

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// No lookup folds an identifier column (0.52). core.users is under FORCE ROW
// LEVEL SECURITY, and PostgreSQL runs nothing that is not leakproof on a column
// ahead of a policy, so `lower(email) = $1` can use no index on the engine's own
// connection: it reads every person, and every test passes, because tests
// connect as a role that bypasses the policy. email_fold and username_fold are
// what a lookup compares. The plan itself is held by store's
// TestFindingSomebodyUsesAnIndexAsTheEngine.
func TestNoLookupFoldsAnIdentifierColumn(t *testing.T) {
	folded := regexp.MustCompile(`(?i)lower\(\s*(\w+\.)?(email|username)\s*\)\s*(=|like\b|in\b|~)`)
	found := 0
	for _, dir := range []string{"engine/internal", "engine/cmd"} {
		err := filepath.WalkDir(filepath.Join(repoRoot(t), dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			found++
			for i, line := range strings.Split(string(raw), "\n") {
				if folded.MatchString(line) {
					t.Errorf("%s:%d folds an identifier column, which no index can serve under row security; "+
						"compare email_fold or username_fold:\n\t%s", path, i+1, strings.TrimSpace(line))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if found < 100 {
		t.Fatalf("read %d files; this test is reading the wrong thing", found)
	}
}
