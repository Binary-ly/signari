package docsync

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every way the engine makes a client says how it authenticates. The column's default is
// client_secret_post, which is wrong for a public client, and five of the seven ways to
// make one relied on it: the command line, the importer, config-as-code, the Admin API's
// create and dynamic registration each stored a public client as sending a secret, and the
// Admin API, the console and Terraform reported it so (migration 0301). This guard found
// the fifth, registration, after the first four were fixed by hand. A statement that names
// the column cannot fall back to it, so a new way in has to decide.
var clientInsert = regexp.MustCompile("(?s)INSERT INTO core\\.clients\\b[^`]*?(?:VALUES|SELECT)")

func TestEveryClientInsertSaysHowItAuthenticates(t *testing.T) {
	engine := filepath.Join(repoRoot(t), "engine")
	found := 0
	err := filepath.WalkDir(engine, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, stmt := range clientInsert.FindAllString(string(raw), -1) {
			found++
			if !strings.Contains(stmt, "token_endpoint_auth_method") {
				rel, _ := filepath.Rel(engine, path)
				t.Errorf("%s inserts a client without naming token_endpoint_auth_method, so a public "+
					"client it makes is stored as client_secret_post: %.120s", rel, strings.Join(strings.Fields(stmt), " "))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < 7 {
		t.Fatalf("only %d client inserts found, so the pattern has stopped matching them", found)
	}
}
