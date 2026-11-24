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
// which takes the row before its first statement does anything (migration
// 0307's trigger runs before the statement) and every other lock after (4.25).
// File-level, so coarse: a file that bumps the version must take the lock
// somewhere. The walk is internal/; the CLI's own bumps, in cmd/signari, come
// after a write whose trigger took the row first.
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
