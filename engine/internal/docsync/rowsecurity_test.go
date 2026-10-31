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

// No large table is searched through the text of a uuid (0.53). `id::text = $1`
// can use no index on any role, the primary key included, so it reads the whole
// table: granting a token did that to core.users, every time. Most such lookups
// are on tables of a few rows and stay as they are; these are the tables that
// grow with the people.
func TestNoPersonIsFoundThroughTheTextOfAnID(t *testing.T) {
	asText := regexp.MustCompile(`(?s)core\.(users|group_members|audit_events|sessions|subject_keys)\b[^` + "`" +
		`]{0,200}?\b(id|user_id|org_id|subject_id|admin_token_id)::text\s*=`)
	for _, dir := range []string{"engine/internal", "engine/cmd"} {
		err := filepath.WalkDir(filepath.Join(repoRoot(t), dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range asText.FindAll(raw, -1) {
				t.Errorf("%s searches a large table through a uuid's text, which no index can serve; "+
					"compare the column and bind store.ExactUUIDOrNil:\n\t%s", path, strings.Join(strings.Fields(string(m)), " "))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
