package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"signari.dev/engine/internal/config"
)

// The command line reads a secret a configuration file names (6.19): from the
// environment, or a file beside the configuration with its last newline
// dropped, and never from a file the engine reads a setting from, under
// whatever name the reference gives it.
func TestALocalSecretIsReadButNeverFromTheEnginesOwnFiles(t *testing.T) {
	dir := t.TempDir()
	read := localSecret(filepath.Join(dir, "signari.yaml"))

	t.Setenv("PROBE_SECRET", "from-the-environment")
	if v, err := read(config.SecretRef{Env: "PROBE_SECRET"}); err != nil || v != "from-the-environment" {
		t.Errorf("the environment gave %q, %v", v, err)
	}
	if _, err := read(config.SecretRef{Env: "PROBE_SECRET_NEVER_SET"}); err == nil ||
		!strings.Contains(err.Error(), "not set") {
		t.Errorf("an unset variable gave %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "pdp.secret"), []byte("from-a-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := read(config.SecretRef{File: "pdp.secret"}); err != nil || v != "from-a-file" {
		t.Errorf("a file beside the configuration gave %q, %v", v, err)
	}

	root := filepath.Join(dir, "root.key")
	if err := os.WriteFile(root, []byte("the root key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(dir, "innocent.secret")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNARI_ROOT_KEY_FILE", root)
	for _, name := range []string{"root.key", "innocent.secret", root} {
		if v, err := read(config.SecretRef{File: name}); err == nil || !strings.Contains(err.Error(), "SIGNARI_ROOT_KEY_FILE") {
			t.Errorf("the root key's file named %s gave %q, %v", name, v, err)
		}
	}
}
