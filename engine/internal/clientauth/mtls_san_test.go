package clientauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// RFC 8705 §2.1 defines FIVE subject forms for tls_client_auth, of which a client
// "uses exactly one": subject_dn, san_dns, san_uri, san_ip and san_email.
//
// Three were implemented. A client whose certificate identifies it by address or
// by mailbox — which is ordinary for service meshes and appliances — could not be
// registered at all: it fell through to "no usable mutual-TLS expectation is
// registered", which is honest and is still a method the RFC defines and we did
// not offer.

// issueWithSANs mints a leaf carrying IP and email SANs, signed by `parent`.
func issueWithSANs(t *testing.T, cn string, ips []net.IP, emails []string,
	parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: cn},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		IPAddresses:    ips,
		EmailAddresses: emails,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func sanRoots(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	ca, caKey := issue(t, "ca", nil, nil, nil, nil, true)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return ca, caKey, pool
}

func TestAnIPAddressSANIsMatched(t *testing.T) {
	ca, caKey, pool := sanRoots(t)
	cert := issueWithSANs(t, "svc", []net.IP{net.ParseIP("10.4.2.1")}, nil, ca, caKey)

	e := TLSExpectation{SANIP: "10.4.2.1"}
	if e.Method() != MethodTLSClientAuth {
		t.Fatalf("an iPAddress expectation reports method %q", e.Method())
	}
	if err := VerifyClientCertificate(stateWith(cert), e, pool); err != nil {
		t.Fatalf("a certificate carrying the registered address was refused: %v", err)
	}

	// A different address must not match.
	if err := VerifyClientCertificate(stateWith(cert), TLSExpectation{SANIP: "10.4.2.2"}, pool); err == nil {
		t.Error("a certificate matched an address it does not carry")
	}
}

// The property a textual comparison would get wrong.
//
// "10.4.2.1" and "010.004.002.001" are the same address and different strings;
// "::1" and "0:0:0:0:0:0:0:1" likewise. Comparing as text refuses a certificate
// that carries exactly the registered address written another way — and invites
// somebody to "fix" it with a normalisation that accepts more than it should.
func TestAnIPAddressIsComparedAsAnAddressNotAsText(t *testing.T) {
	ca, caKey, pool := sanRoots(t)
	cert := issueWithSANs(t, "svc", []net.IP{net.ParseIP("2001:db8::1")}, nil, ca, caKey)

	for _, spelling := range []string{
		"2001:db8::1",
		"2001:0db8:0000:0000:0000:0000:0000:0001",
		"2001:DB8::1",
	} {
		if err := VerifyClientCertificate(stateWith(cert), TLSExpectation{SANIP: spelling}, pool); err != nil {
			t.Errorf("%q did not match the same address in the certificate: %v", spelling, err)
		}
	}

	// And an IPv4 address must not match an IPv6 one.
	if err := VerifyClientCertificate(stateWith(cert), TLSExpectation{SANIP: "10.4.2.1"}, pool); err == nil {
		t.Error("an IPv4 expectation matched an IPv6-only certificate")
	}
}

// A registered value that is not an address must fail loudly rather than
// silently matching nothing — the operator has made a typo, not a policy.
func TestAMalformedRegisteredAddressIsReported(t *testing.T) {
	ca, caKey, pool := sanRoots(t)
	cert := issueWithSANs(t, "svc", []net.IP{net.ParseIP("10.4.2.1")}, nil, ca, caKey)

	err := VerifyClientCertificate(stateWith(cert), TLSExpectation{SANIP: "10.4.2.256"}, pool)
	if err == nil {
		t.Fatal("a malformed registered address was accepted")
	}
	if !contains(err.Error(), "not an IP address") {
		t.Errorf("the error does not say the registered value is malformed: %v", err)
	}
}

func TestAnEmailSANIsMatchedCaseInsensitively(t *testing.T) {
	ca, caKey, pool := sanRoots(t)
	cert := issueWithSANs(t, "svc", nil, []string{"Robot@Example.Test"}, ca, caKey)

	for _, spelling := range []string{"Robot@Example.Test", "robot@example.test", "ROBOT@EXAMPLE.TEST"} {
		if err := VerifyClientCertificate(stateWith(cert), TLSExpectation{SANEmail: spelling}, pool); err != nil {
			t.Errorf("%q did not match: %v", spelling, err)
		}
	}

	// No normalisation beyond case: these are different mailboxes.
	for _, other := range []string{"ro.bot@example.test", "robot+tag@example.test", "robot@example.test.evil"} {
		if err := VerifyClientCertificate(stateWith(cert), TLSExpectation{SANEmail: other}, pool); err == nil {
			t.Errorf("%q matched a different mailbox", other)
		}
	}
}

// A certificate with no SANs at all must not satisfy an expectation of either
// kind — the empty-loop case, which is how a matcher accidentally passes.
func TestACertificateWithNoSANsMatchesNothing(t *testing.T) {
	ca, caKey, pool := sanRoots(t)
	cert := issueWithSANs(t, "svc", nil, nil, ca, caKey)

	if err := VerifyClientCertificate(stateWith(cert), TLSExpectation{SANIP: "10.4.2.1"}, pool); err == nil {
		t.Error("a certificate with no iPAddress SAN satisfied an address expectation")
	}
	if err := VerifyClientCertificate(stateWith(cert), TLSExpectation{SANEmail: "robot@example.test"}, pool); err == nil {
		t.Error("a certificate with no rfc822Name SAN satisfied an email expectation")
	}
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
