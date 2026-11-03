package keys

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A module half-configured is refused at load, before anything is signed or
// made: a token unnamed, a PIN missing or given twice, or a PIN file others can
// read.
func TestAModuleIsConfiguredCompletelyOrRefused(t *testing.T) {
	loose := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(loose, []byte("1234"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := map[string]string{
		"SIGNARI_ROOT_KEY":      base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"SIGNARI_PKCS11_MODULE": "/nowhere/libmodule.so",
		"SIGNARI_PKCS11_TOKEN":  "signing",
		"SIGNARI_PKCS11_PIN":    "1234",
	}
	for _, c := range []struct {
		name string
		set  map[string]string
		want string
	}{
		{"no token", map[string]string{"SIGNARI_PKCS11_TOKEN": ""}, "SIGNARI_PKCS11_TOKEN is not"},
		{"no PIN", map[string]string{"SIGNARI_PKCS11_PIN": ""}, "neither SIGNARI_PKCS11_PIN"},
		{"two PINs", map[string]string{"SIGNARI_PKCS11_PIN_FILE": loose}, "both set"},
		{"a PIN file others read", map[string]string{"SIGNARI_PKCS11_PIN": "", "SIGNARI_PKCS11_PIN_FILE": loose}, "mode 0644"},
	} {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		for k, v := range c.set {
			env[k] = v
		}
		_, err := LoadRootKeyring(func(k string) string { return env[k] })
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error saying %q", c.name, err, c.want)
		}
	}
	delete(base, "SIGNARI_PKCS11_MODULE")
	ring, err := LoadRootKeyring(func(k string) string { return base[k] })
	if err != nil || ring.backend != nil {
		t.Errorf("no module named: %v, backend %v", err, ring.backend)
	}
}

// Every signing key is made through the keyring, which makes it in the module
// when there is one. A call to the package's own Generate, GenerateSized or
// Successor makes it in software whatever is configured, so a rotation
// reached that way would quietly move a deployment's keys out of its module.
// Derived from the source, so a new caller is seen without being listed.
func TestEverySigningKeyIsMadeWhereTheKeyringMakesThem(t *testing.T) {
	// The one key made in software on purpose: it opens, and a module here
	// signs only (backend.go).
	allowed := map[string]string{
		"internal/keys/decrypt.go": "the wallet encryption key",
	}
	outside := regexp.MustCompile(`\bkeys\.(Generate|GenerateSized|Successor)\(`)
	// Not at the start of a line, where it is the Backend interface's method.
	inside := regexp.MustCompile(`[^.\w](Generate|GenerateSized|Successor)\(`)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var seen int
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		src, err := os.ReadFile(path) // #nosec G304 -- this repository's own source
		if err != nil {
			return err
		}
		pattern := outside
		if filepath.Dir(rel) == "internal/keys" {
			pattern = inside
		}
		for i, line := range strings.Split(string(src), "\n") {
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "//") || strings.HasPrefix(code, "func ") || !pattern.MatchString(code) {
				continue
			}
			seen++
			if _, ok := allowed[rel]; !ok {
				t.Errorf("%s:%d makes a key in software whatever the node is given: %s", rel, i+1, code)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen == 0 {
		t.Error("found no call at all, so the search is looking in the wrong place")
	}
}
