package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/google/uuid"
)

// What a key toward an upstream identity provider is for, as
// core.saml_source_keys.purpose names it.
const (
	SPKeySigning    = "signing"
	SPKeyEncryption = "encryption"
)

// spKeyBits is the size of a key this deployment makes for itself. RSA, since
// assertion encryption needs it and a provider that insists on signed requests
// is far likelier to verify RSA than anything else.
const spKeyBits = 3072

// SPKey is a key toward one upstream, usable behind crypto's interfaces and so,
// should it come to that, from outside the process (ADR-009).
type SPKey interface {
	crypto.Signer
	crypto.Decrypter
}

// NewSPKey makes a key and a certificate for it, returning the key as PKCS#8 for
// the caller to seal. A certificate is how a provider takes a public key, and
// says nothing else: see selfSign on why it is self-signed.
func NewSPKey(issuer, purpose string) (pkcs8 []byte, certPEM string, err error) {
	usage := x509.KeyUsageDigitalSignature
	switch purpose {
	case SPKeySigning:
	case SPKeyEncryption:
		usage = x509.KeyUsageKeyEncipherment
	default:
		return nil, "", fmt.Errorf("a key is for %q or %q, not %q", SPKeySigning, SPKeyEncryption, purpose)
	}
	key, err := rsa.GenerateKey(rand.Reader, spKeyBits)
	if err != nil {
		return nil, "", fmt.Errorf("generating a key: %w", err)
	}
	der, _, err := selfSignFor(issuer, purpose+" "+uuid.NewString(), key, usage)
	if err != nil {
		return nil, "", err
	}
	pkcs8, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("encoding the key: %w", err)
	}
	return pkcs8, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// ParseSPKey reads back what NewSPKey made.
func ParseSPKey(pkcs8 []byte) (SPKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("reading a key: %w", err)
	}
	sp, ok := key.(SPKey)
	if !ok {
		return nil, fmt.Errorf("a key toward an upstream is a %T, which cannot sign and decrypt", key)
	}
	return sp, nil
}
