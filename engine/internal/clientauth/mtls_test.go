package clientauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

// issue makes a certificate, optionally signed by a parent.
func issue(t *testing.T, cn string, dns []string, uris []string,
	parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []*url.URL
	for _, u := range uris {
		p, perr := url.Parse(u)
		if perr != nil {
			t.Fatal(perr)
		}
		parsed = append(parsed, p)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     dns,
		URIs:         parsed,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func stateWith(certs ...*x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: certs}
}

// TestSelfSignedMatchesOnThumbprintOnly.
//
// A self-signed certificate has no issuer worth trusting, so the certificate
// itself is the credential and nothing but an exact match will do.
func TestSelfSignedMatchesOnThumbprintOnly(t *testing.T) {
	cert, _ := issue(t, "svc", nil, nil, nil, nil, false)
	other, _ := issue(t, "svc", nil, nil, nil, nil, false) // same subject!

	sum := thumb(cert)
	exp := TLSExpectation{Thumbprint: sum}

	if err := VerifyClientCertificate(stateWith(cert), exp, nil); err != nil {
		t.Fatalf("the registered certificate was refused: %v", err)
	}
	// Same common name, different key: must NOT be accepted. This is the whole
	// difference between matching a name and matching a credential.
	if err := VerifyClientCertificate(stateWith(other), exp, nil); err == nil {
		t.Error("a different certificate with the same subject was accepted")
	}
}

// TestPKIRequiresATrustedChain is the check that stops a subject string being an
// identity: without it, anybody who can write "CN=payments" into a certificate
// they signed themselves authenticates as that client.
func TestPKIRequiresATrustedChain(t *testing.T) {
	ca, caKey := issue(t, "Test CA", nil, nil, nil, nil, true)
	good, _ := issue(t, "payments", []string{"payments.example.test"}, nil, ca, caKey, false)
	forged, _ := issue(t, "payments", []string{"payments.example.test"}, nil, nil, nil, false)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	exp := TLSExpectation{SANDNS: "payments.example.test"}

	if err := VerifyClientCertificate(stateWith(good), exp, roots); err != nil {
		t.Fatalf("a CA-issued certificate was refused: %v", err)
	}
	// Identical name and SAN, self-signed. Refused because it chains to nothing.
	if err := VerifyClientCertificate(stateWith(forged), exp, roots); err == nil {
		t.Error("a self-signed certificate carrying the expected SAN was accepted")
	}
	// And with no authority configured, the method is refused outright rather
	// than quietly downgraded to trusting whatever was sent.
	err := VerifyClientCertificate(stateWith(good), exp, nil)
	if err == nil {
		t.Error("tls_client_auth succeeded with no trusted authority configured")
	}
	if !strings.Contains(err.Error(), "SIGNARI_TLS_CLIENT_CA") {
		t.Errorf("the error should name the missing configuration: %v", err)
	}
}

func TestSubjectAndURIMatching(t *testing.T) {
	ca, caKey := issue(t, "Test CA", nil, nil, nil, nil, true)
	cert, _ := issue(t, "payments-service", []string{"a.test"},
		[]string{"spiffe://example/ns/prod/sa/payments"}, ca, caKey, false)
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	if err := VerifyClientCertificate(stateWith(cert),
		TLSExpectation{SubjectDN: cert.Subject.String()}, roots); err != nil {
		t.Errorf("subject DN match failed: %v", err)
	}
	if err := VerifyClientCertificate(stateWith(cert),
		TLSExpectation{SubjectDN: "CN=somebody-else"}, roots); err == nil {
		t.Error("a wrong subject DN was accepted")
	}
	if err := VerifyClientCertificate(stateWith(cert),
		TLSExpectation{SANURI: "spiffe://example/ns/prod/sa/payments"}, roots); err != nil {
		t.Errorf("URI SAN match failed: %v", err)
	}
	if err := VerifyClientCertificate(stateWith(cert),
		TLSExpectation{SANURI: "spiffe://example/ns/prod/sa/billing"}, roots); err == nil {
		t.Error("a wrong URI SAN was accepted")
	}
	// DNS matching is case-insensitive because DNS is, and exact otherwise --
	// no wildcards, since a wildcard client identity means a whole namespace can
	// authenticate as this client.
	if err := VerifyClientCertificate(stateWith(cert),
		TLSExpectation{SANDNS: "A.TEST"}, roots); err != nil {
		t.Errorf("DNS matching was case-sensitive: %v", err)
	}
	if err := VerifyClientCertificate(stateWith(cert),
		TLSExpectation{SANDNS: "*.test"}, roots); err == nil {
		t.Error("a wildcard SAN expectation matched")
	}
}

func TestNoCertificateAndNoExpectation(t *testing.T) {
	cert, _ := issue(t, "svc", nil, nil, nil, nil, false)
	if err := VerifyClientCertificate(nil, TLSExpectation{Thumbprint: thumb(cert)}, nil); err == nil {
		t.Error("a nil TLS state was accepted")
	}
	if err := VerifyClientCertificate(stateWith(), TLSExpectation{Thumbprint: thumb(cert)}, nil); err == nil {
		t.Error("a connection with no peer certificate was accepted")
	}
	if err := VerifyClientCertificate(stateWith(cert), TLSExpectation{}, nil); err == nil {
		t.Error("a client with no mutual-TLS registration was authenticated by one")
	}
}

// TestThumbprintEncoding pins the RFC 8705 §3.1 form. The value must be
// identical at issuance and at every later use, so the encoding is not a detail.
func TestThumbprintEncoding(t *testing.T) {
	cert, _ := issue(t, "svc", nil, nil, nil, nil, false)
	got := CertificateThumbprint(cert)
	if strings.ContainsAny(got, "+/=") {
		t.Errorf("thumbprint %q is not base64url without padding", got)
	}
	if len(got) != 43 { // 32 bytes -> 43 base64url characters, unpadded
		t.Errorf("thumbprint is %d characters, want 43", len(got))
	}
	if CertificateThumbprint(cert) != got {
		t.Error("the thumbprint is not stable across calls")
	}
	if ThumbprintFromState(stateWith(cert)) != got {
		t.Error("ThumbprintFromState disagrees with CertificateThumbprint")
	}
	if ThumbprintFromState(nil) != "" {
		t.Error("a nil state produced a thumbprint")
	}
}

func TestMethodNaming(t *testing.T) {
	cert, _ := issue(t, "svc", nil, nil, nil, nil, false)
	if m := (TLSExpectation{Thumbprint: thumb(cert)}).Method(); m != MethodSelfSignedTLSClientAuth {
		t.Errorf("thumbprint expectation reported %q", m)
	}
	if m := (TLSExpectation{SANDNS: "a.test"}).Method(); m != MethodTLSClientAuth {
		t.Errorf("SAN expectation reported %q", m)
	}
	if (TLSExpectation{}).Configured() {
		t.Error("an empty expectation reports configured")
	}
}

func thumb(c *x509.Certificate) []byte {
	sum := sha256Of(c.Raw)
	return sum
}
