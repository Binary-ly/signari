package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func selfSignedPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "partner"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A document that lists the same keys in another order has changed nothing, and a
// refresh that said it had would teach whoever reads it to stop reading.
func TestTheOrderOfAPartnersKeysIsNotAChange(t *testing.T) {
	a, b := selfSignedPEM(t), selfSignedPEM(t)
	if fingerprints(a+b) != fingerprints(b+a) {
		t.Error("two certificates in another order read as a change")
	}
	if fingerprints(a) == fingerprints(a+b) || fingerprints("") != "" {
		t.Error("a certificate added reads as nothing")
	}
	if got := fingerprints(a + b); len(strings.Fields(got)) != 2 {
		t.Errorf("fingerprints %q", got)
	}
}

// A further endpoint is held to the rule of the first: it receives a credential.
func TestEveryEndpointOfAProviderIsHeldToTheSameRule(t *testing.T) {
	for _, bad := range []string{"http://sp.example.test/acs", "https://*.example.test/acs"} {
		s := SAMLProviderSpec{EntityID: "https://sp.example.test", ACSURL: "https://sp.example.test/acs",
			MoreACSURLs: []string{bad}}
		if err := s.Validate(); err == nil {
			t.Errorf("%s was accepted beside a good one", bad)
		}
	}
}

// The second certificate of a rotation is read as carefully as the first.
func TestEveryCertificateOfARotationIsChecked(t *testing.T) {
	good := selfSignedPEM(t)
	broken := good + "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	s := SAMLProviderSpec{EntityID: "https://sp.example.test", ACSURL: "https://sp.example.test/acs", SigningCertPEM: broken}
	if err := s.Validate(); err == nil {
		t.Error("a service provider's second certificate was not read")
	}
	u := IdentityProviderSpec{Slug: "corp", Kind: "saml", EntityID: "https://idp.example.test",
		SSOURL: "https://idp.example.test/sso", CertPEM: broken}
	if err := u.Validate(); err == nil {
		t.Error("an upstream's second certificate was not read")
	}
}
