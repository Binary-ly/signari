package saml

import (
	"crypto/x509"
	"net/url"
	"strings"
	"testing"
	"time"
)

func spKeyFor(t *testing.T, purpose string) (SPKey, string) {
	t.Helper()
	pkcs8, certPEM, err := NewSPKey("https://signin.example.test", purpose)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseSPKey(pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	return key, certPEM
}

func TestAKeyIsCertifiedForWhatItIsFor(t *testing.T) {
	for purpose, usage := range map[string]x509.KeyUsage{
		SPKeySigning: x509.KeyUsageDigitalSignature, SPKeyEncryption: x509.KeyUsageKeyEncipherment} {
		_, certPEM := spKeyFor(t, purpose)
		certs, err := ParseCertificates(certPEM)
		if err != nil || len(certs) != 1 {
			t.Fatalf("%s: %v", purpose, err)
		}
		if certs[0].KeyUsage != usage {
			t.Errorf("%s: the certificate says %v", purpose, certs[0].KeyUsage)
		}
	}
	if _, _, err := NewSPKey("https://signin.example.test", "decoration"); err == nil {
		t.Error("a key for nothing was made")
	}
}

// A signed request verified the way an identity provider verifies one, which here
// is the code that does it for the service providers talking to this engine: the
// bytes signed have to be the bytes sent, through a URL that had a query already.
func TestASignedRequestVerifiesAsAProviderVerifiesIt(t *testing.T) {
	key, certPEM := spKeyFor(t, SPKeySigning)
	p := &InboundProvider{SSOURL: "https://idp.example.test/sso?tenant=a%20b", SPEntityID: "https://sp.example.test",
		ACSURL: "https://sp.example.test/acs", SignRequests: true}

	if _, err := BuildAuthnRequest(p, "relay", time.Now()); err == nil {
		t.Fatal("a request to be signed was built with nothing to sign it")
	}
	p.RequestSigner = key
	out, err := BuildAuthnRequest(p, "relay/with+odd&chars", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(out.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("tenant") != "a b" {
		t.Errorf("the URL lost its own query: %s", out.RedirectURL)
	}
	if err := VerifyRedirectSignature(u.RawQuery, certPEM, "SAMLRequest"); err != nil {
		t.Fatalf("the signature did not verify: %v", err)
	}
	tampered := strings.Replace(u.RawQuery, "RelayState=relay", "RelayState=other", 1)
	if err := VerifyRedirectSignature(tampered, certPEM, "SAMLRequest"); err == nil {
		t.Error("a changed RelayState verified")
	}
	_, other := spKeyFor(t, SPKeySigning)
	if err := VerifyRedirectSignature(u.RawQuery, other, "SAMLRequest"); err == nil {
		t.Error("it verified against somebody else's certificate")
	}

	p.SignRequests = false
	plain, err := BuildAuthnRequest(p, "relay", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.RedirectURL, "Signature=") {
		t.Errorf("a request nobody asked to sign was signed: %s", plain.RedirectURL)
	}
}
