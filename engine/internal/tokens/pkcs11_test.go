//go:build pkcs11 && cgo

package tokens

import (
	"testing"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/keys/softhsm"
)

func TestMain(m *testing.M) { softhsm.Main(m) }

func TestATokenSignedInAModuleVerifies(t *testing.T) {
	module, label, pin := softhsm.Token(t)
	heldKeysSignTokens(t, heldRing(t, map[string]string{
		"SIGNARI_PKCS11_MODULE": module,
		"SIGNARI_PKCS11_TOKEN":  label,
		"SIGNARI_PKCS11_PIN":    pin,
	}), keys.EdDSA)
}
