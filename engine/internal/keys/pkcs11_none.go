//go:build !pkcs11 || !cgo

package keys

import "fmt"

// A build without PKCS#11 (pkcs11.go) refuses a module rather than ignoring it:
// ignored, the setting would leave every new key made in software by a node its
// operator believes keeps them in hardware.
func newPKCS11(module, token, pin string) (Backend, error) {
	return nil, fmt.Errorf("SIGNARI_PKCS11_MODULE is set, and this build has no PKCS#11; " +
		"use the pkcs11 image, or build with CGO_ENABLED=1 -tags pkcs11")
}
