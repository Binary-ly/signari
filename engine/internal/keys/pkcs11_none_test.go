//go:build !pkcs11 || !cgo

package keys

import (
	"encoding/base64"
	"strings"
	"testing"
)

// A build without PKCS#11 refuses a module it is given rather than making keys
// in software beside it.
func TestABuildWithoutPKCS11RefusesAModule(t *testing.T) {
	env := map[string]string{
		"SIGNARI_ROOT_KEY":      base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"SIGNARI_PKCS11_MODULE": "/usr/lib/softhsm/libsofthsm2.so",
		"SIGNARI_PKCS11_TOKEN":  "signing",
		"SIGNARI_PKCS11_PIN":    "1234",
	}
	if _, err := LoadRootKeyring(func(k string) string { return env[k] }); err == nil ||
		!strings.Contains(err.Error(), "-tags pkcs11") {
		t.Errorf("a build without PKCS#11 took a module: %v", err)
	}
}
