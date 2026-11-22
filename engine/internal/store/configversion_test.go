package store

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every writer outside the CLI that moves the configuration version itself
// takes the row first (LockConfigVersion), or it deadlocks with a CLI write,
// which takes the row at its first statement and the audit chain's lock after
// (4.25). File-level, so coarse: a file that bumps the version must take the
// lock somewhere. The CLI's own bumps, in cmd/signari, follow a write its
// trigger already took the row for.
func TestEveryVersionBumpTakesTheRowFirst(t *testing.T) {
	var bumps []string
	if err := filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "UPDATE core.config_version") {
			bumps = append(bumps, p)
			if !strings.Contains(string(b), "LockConfigVersion(") {
				t.Errorf("%s moves the configuration version and never takes its row first "+
					"(store.LockConfigVersion), so it can deadlock with a CLI write", p)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(bumps) < 3 {
		t.Fatalf("found %d files that move the version (%v); the walk is wrong", len(bumps), bumps)
	}
}
