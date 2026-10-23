package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"signari.dev/engine/internal/config"
	"signari.dev/engine/internal/keys"
)

// localSecret reads a secret the configuration file at configPath names by
// reference (6.19): from this process's environment, or from a file, a
// relative one beside the configuration. Only the command line reads one; the
// Admin API refuses a file that names any, since there it would read the
// server's.
func localSecret(configPath string) func(config.SecretRef) (string, error) {
	dir := filepath.Dir(configPath)
	return func(ref config.SecretRef) (string, error) {
		if ref.Env != "" {
			v, ok := os.LookupEnv(ref.Env)
			if !ok {
				return "", fmt.Errorf("%s is not set", ref.Env)
			}
			return v, nil
		}
		path := ref.File
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		info, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		// Never a file the engine reads its own settings from, the root key's
		// above all, whatever it is called here: the reference beside a URL
		// would send it there.
		for _, kv := range os.Environ() {
			name, value, _ := strings.Cut(kv, "=")
			if !strings.HasPrefix(name, "SIGNARI_") || !strings.HasSuffix(name, "_FILE") || value == "" {
				continue
			}
			if setting, err := os.Stat(value); err == nil && os.SameFile(info, setting) {
				return "", fmt.Errorf("%s is the file %s names, a setting of the engine and never another "+
					"system's secret", ref.File, name)
			}
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- the operator names the file
		if err != nil {
			return "", err
		}
		// One trailing newline is how a file of one line ends, not part of it.
		return strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r"), nil
	}
}

// rootKeyIfGiven is the root key when this process is given one, and nil
// otherwise: a file that declares nothing holding a secret is planned and
// applied without it, and the plan refuses one that needs it, saying why.
func rootKeyIfGiven() (*keys.RootKey, error) {
	if os.Getenv("SIGNARI_ROOT_KEY") == "" && os.Getenv("SIGNARI_ROOT_KEY_FILE") == "" {
		return nil, nil
	}
	return rootKey()
}
