//go:build pkcs11 && cgo

// Package softhsm gives the tests that need a PKCS#11 module a SoftHSM token of
// their own, with a label and PIN made up for the run.
package softhsm

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// Where SoftHSM 2 puts its module: Homebrew on Apple silicon and on Intel, then
// the Debian and Ubuntu packages. SIGNARI_TEST_PKCS11_MODULE names another.
var modules = []string{
	"/opt/homebrew/lib/softhsm/libsofthsm2.so",
	"/usr/local/lib/softhsm/libsofthsm2.so",
	"/usr/lib/softhsm/libsofthsm2.so",
	"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
	"/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
}

var made struct {
	once                    sync.Once
	dir, module, label, pin string
	err                     error
}

// Token is the run's token. There is one per test binary: a module reads its
// configuration when it is first loaded and stays loaded, so a second token
// directory set later would never be seen. A build asked for PKCS#11 and given
// no SoftHSM fails rather than skips, since a skip would pass a run that tested
// nothing.
func Token(t testing.TB) (module, label, pin string) {
	t.Helper()
	made.once.Do(func() { made.err = initialise() })
	if made.err != nil {
		t.Fatalf("a SoftHSM token for the PKCS#11 tests: %v", made.err)
	}
	return made.module, made.label, made.pin
}

// Main runs the tests and removes the token afterwards.
func Main(m *testing.M) {
	code := m.Run()
	if made.dir != "" {
		_ = os.RemoveAll(made.dir)
	}
	os.Exit(code)
}

func initialise() error {
	made.module = os.Getenv("SIGNARI_TEST_PKCS11_MODULE")
	for _, m := range modules {
		if made.module != "" {
			break
		}
		if _, err := os.Stat(m); err == nil {
			made.module = m
		}
	}
	if made.module == "" {
		return fmt.Errorf("no SoftHSM module in %v; install softhsm or set SIGNARI_TEST_PKCS11_MODULE", modules)
	}
	dir, err := os.MkdirTemp("", "signari-softhsm-")
	if err != nil {
		return err
	}
	made.dir = dir
	tokens := filepath.Join(dir, "tokens")
	if err := os.Mkdir(tokens, 0o700); err != nil {
		return err
	}
	conf := filepath.Join(dir, "softhsm2.conf")
	if err := os.WriteFile(conf, []byte("directories.tokendir = "+tokens+"\nobjectstore.backend = file\n"), 0o600); err != nil {
		return err
	}
	if err := os.Setenv("SOFTHSM2_CONF", conf); err != nil {
		return err
	}
	made.label, made.pin = "signari-"+random(4), random(8)
	out, err := exec.Command("softhsm2-util", "--init-token", "--free", "--label", made.label,
		"--pin", made.pin, "--so-pin", random(8)).CombinedOutput() // #nosec G204 -- fixed program, made-up values
	if err != nil {
		return fmt.Errorf("softhsm2-util --init-token: %v: %s", err, out)
	}
	return nil
}

func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
