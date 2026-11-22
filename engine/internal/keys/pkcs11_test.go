//go:build pkcs11 && cgo

package keys

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"testing"

	"signari.dev/engine/internal/keys/softhsm"
)

func TestMain(m *testing.M) { softhsm.Main(m) }

// moduleRing is a keyring given the run's SoftHSM token the way a node is, by
// its settings.
func moduleRing(t *testing.T, ref string) *RootKey {
	t.Helper()
	module, label, pin := softhsm.Token(t)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	pinFile := t.TempDir() + "/pin"
	if err := os.WriteFile(pinFile, []byte(pin+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"SIGNARI_ROOT_KEY":        base64.StdEncoding.EncodeToString(secret),
		"SIGNARI_ROOT_KEY_REF":    ref,
		"SIGNARI_PKCS11_MODULE":   module,
		"SIGNARI_PKCS11_TOKEN":    label,
		"SIGNARI_PKCS11_PIN_FILE": pinFile,
	}
	ring, err := LoadRootKeyring(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if ring.backend == nil || ring.backend.Scheme() != "pkcs11" {
		t.Fatal("the keyring was given a module and holds none")
	}
	return ring
}

func TestSigningKeysAreMadeAndKeptInAPKCS11Token(t *testing.T) {
	heldKeysAreMadeKeptAndRotated(t, moduleRing(t, "pkcs11-test"), "SIGNARI_PKCS11_MODULE")
}

func TestAKeyMadeBeforeTheModuleIsSucceededByOneInIt(t *testing.T) {
	heldKeySucceedsASealedOne(t, moduleRing(t, "pkcs11-move"))
}

func TestAKeyTheTokenHoldsIsTheKeyThatWasPublished(t *testing.T) {
	heldKeyMustBeThePublishedOne(t, moduleRing(t, "pkcs11-swap"))
}

func TestARootKeyRotationLeavesTokenKeysAlone(t *testing.T) {
	rootRotationLeavesHeldKeys(t, moduleRing(t, "old"))
}

func TestTheTokenMakesEveryAlgorithmButEdDSA(t *testing.T) {
	everyAlgorithmIsMadeHeld(t, moduleRing(t, "pkcs11-algs"), EdDSA)
}
