package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// spKeyPair is a service provider's signing key, as it would be registered.
type spKeyPair struct {
	key     *rsa.PrivateKey
	cert    *x509.Certificate
	certPEM string
}

func newSPKeyPair(t *testing.T) *spKeyPair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &spKeyPair{
		key:     key,
		cert:    cert,
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
}

// keyStore adapts the pair to goxmldsig's signing interface.
type keyStore struct{ p *spKeyPair }

func (k keyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return k.p.key, k.p.cert.Raw, nil
}

// signRequest produces a genuinely signed AuthnRequest, the way a service
// provider's own library would.
func signRequest(t *testing.T, p *spKeyPair, id string) string {
	t.Helper()
	unsigned := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + id + `" Version="2.0" ` +
		`IssueInstant="2026-01-01T00:00:00Z" Destination="https://idp.test/saml/sso" ` +
		`AssertionConsumerServiceURL="https://sp.test/acs">` +
		`<saml:Issuer>https://sp.test</saml:Issuer></samlp:AuthnRequest>`

	doc := etree.NewDocument()
	if err := doc.ReadFromString(unsigned); err != nil {
		t.Fatal(err)
	}
	sctx := dsig.NewDefaultSigningContext(keyStore{p})
	if err := sctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	signed, err := sctx.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	s, err := out.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignedRequestVerifies(t *testing.T) {
	p := newSPKeyPair(t)
	doc := signRequest(t, p, "_req-1")
	if err := VerifyEmbeddedSignature([]byte(doc), p.certPEM, "AuthnRequest", "_req-1"); err != nil {
		t.Fatalf("a correctly signed request was refused: %v", err)
	}
}

func TestUnsignedRequestIsRefused(t *testing.T) {
	p := newSPKeyPair(t)
	unsigned := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`ID="_req-1" Version="2.0"><Issuer>https://sp.test</Issuer></samlp:AuthnRequest>`
	err := VerifyEmbeddedSignature([]byte(unsigned), p.certPEM, "AuthnRequest", "_req-1")
	if err == nil {
		t.Fatal("an unsigned request was accepted by a provider that requires signing")
	}
	// The message names the element received, so a LogoutRequest refusal does not
	// talk about AuthnRequests.
	if !strings.Contains(err.Error(), "AuthnRequest carries no signature") {
		t.Errorf("the error should name the unsigned AuthnRequest; got %v", err)
	}
}

// TestTamperedRequestIsRefused -- the signature must actually cover the content.
func TestTamperedSignedRequestIsRefused(t *testing.T) {
	p := newSPKeyPair(t)
	doc := signRequest(t, p, "_req-1")
	// Move the assertion consumer service somewhere the attacker controls.
	tampered := strings.Replace(doc, "https://sp.test/acs", "https://evil.test/acs", 1)
	if tampered == doc {
		t.Fatal("the test did not modify the document")
	}
	if err := VerifyEmbeddedSignature([]byte(tampered), p.certPEM, "AuthnRequest", "_req-1"); err == nil {
		t.Fatal("a request whose ACS URL was changed after signing was accepted")
	}
}

// TestAnotherProvidersSignatureIsRefused. The certificate is the whole point:
// a valid signature by the wrong party is not authentication.
func TestAnotherProvidersSignatureIsRefused(t *testing.T) {
	mine, theirs := newSPKeyPair(t), newSPKeyPair(t)
	doc := signRequest(t, theirs, "_req-1")
	if err := VerifyEmbeddedSignature([]byte(doc), mine.certPEM, "AuthnRequest", "_req-1"); err == nil {
		t.Fatal("a request signed by a different key was accepted")
	}
}

// TestSignatureWrappingIsRefused is the attack this file exists for.
//
// The attacker takes a genuinely signed request, wraps it inside a new document
// whose root is their own forged request, and hopes the verifier finds the real
// signature while the application reads the forged content. goxmldsig searches
// the whole tree for a signature, so the structural rules are what stop this.
func TestSignatureWrappingIsRefused(t *testing.T) {
	p := newSPKeyPair(t)
	genuine := signRequest(t, p, "_req-1")

	doc := etree.NewDocument()
	if err := doc.ReadFromString(genuine); err != nil {
		t.Fatal(err)
	}
	realRoot := doc.Root()

	// Forge a request that says something different, and bury the genuine signed
	// one inside it.
	forged := etree.NewElement("AuthnRequest")
	forged.Space = "samlp"
	forged.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	forged.CreateAttr("ID", "_req-1") // same ID, so the Reference still resolves
	forged.CreateAttr("Version", "2.0")
	forged.CreateAttr("AssertionConsumerServiceURL", "https://evil.test/acs")
	iss := forged.CreateElement("Issuer")
	iss.SetText("https://sp.test")

	// The classic hiding place: an Extensions element carrying the original.
	ext := forged.CreateElement("Extensions")
	ext.AddChild(realRoot.Copy())

	out := etree.NewDocument()
	out.SetRoot(forged)
	wrapped, err := out.WriteToString()
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyEmbeddedSignature([]byte(wrapped), p.certPEM, "AuthnRequest", "_req-1")
	if err == nil {
		t.Fatal("a signature-wrapped request was accepted: the signature covered the " +
			"buried original while the ACS URL read from the document was the attacker's")
	}
	t.Logf("refused with: %v", err)
}

// TestSignatureNotOnTheRootIsRefused -- the narrower version of wrapping, where
// the signature is valid but covers a child element.
func TestSignatureNotOnTheRootIsRefused(t *testing.T) {
	p := newSPKeyPair(t)
	genuine := signRequest(t, p, "_inner")

	doc := etree.NewDocument()
	if err := doc.ReadFromString(genuine); err != nil {
		t.Fatal(err)
	}
	outer := etree.NewElement("AuthnRequest")
	outer.Space = "samlp"
	outer.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	outer.CreateAttr("ID", "_outer")
	outer.CreateAttr("Version", "2.0")
	outer.AddChild(doc.Root().Copy())

	out := etree.NewDocument()
	out.SetRoot(outer)
	s, err := out.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyEmbeddedSignature([]byte(s), p.certPEM, "AuthnRequest", "_outer")
	if err == nil {
		t.Fatal("a request was accepted on the strength of a signature over a child element")
	}
	// The IDs here are deliberately distinct, so the duplicate-ID rule cannot be
	// what refuses this. Asserting the reason keeps the placement check honest:
	// without it, this document has one valid signature and no duplicate IDs, and
	// would otherwise sail through.
	if !strings.Contains(err.Error(), "direct child") {
		t.Errorf("expected the placement rule to refuse this, got: %v", err)
	}
}

// TestDuplicateIDsAreRefused. Two elements with one ID is the precondition for
// the verifier and the parser resolving a reference differently.
func TestDuplicateIDsAreRefused(t *testing.T) {
	p := newSPKeyPair(t)
	genuine := signRequest(t, p, "_req-1")

	doc := etree.NewDocument()
	if err := doc.ReadFromString(genuine); err != nil {
		t.Fatal(err)
	}
	decoy := doc.Root().CreateElement("Decoy")
	decoy.CreateAttr("ID", "_req-1")

	out := etree.NewDocument()
	out.SetRoot(doc.Root().Copy())
	s, err := out.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyEmbeddedSignature([]byte(s), p.certPEM, "AuthnRequest", "_req-1")
	if err == nil {
		t.Fatal("a document with two elements carrying the same ID was accepted")
	}
	if !strings.Contains(err.Error(), "ID") {
		t.Errorf("the error should name the duplicate ID; got %v", err)
	}
}

// TestNoCertificateMeansRefusal. "Required but unverifiable" must fail closed --
// a provider configured to demand signatures with no certificate on file must
// not silently fall back to accepting anything.
func TestNoCertificateMeansRefusal(t *testing.T) {
	p := newSPKeyPair(t)
	doc := signRequest(t, p, "_req-1")
	err := VerifyEmbeddedSignature([]byte(doc), "", "AuthnRequest", "_req-1")
	if err == nil {
		t.Fatal("a request was accepted for a provider with no registered certificate")
	}
	if !strings.Contains(err.Error(), "no signing certificate") {
		t.Errorf("the error should say no certificate is registered; got %v", err)
	}
}

// TestIDMismatchIsRefused. The element verified and the element acted on must be
// the same one, and the ID is how that is asserted.
func TestIDMismatchIsRefused(t *testing.T) {
	p := newSPKeyPair(t)
	doc := signRequest(t, p, "_req-1")
	if err := VerifyEmbeddedSignature([]byte(doc), p.certPEM, "AuthnRequest", "_something-else"); err == nil {
		t.Fatal("the signature was checked against an ID other than the one parsed")
	}
}

// TestCommentsAreRefusedHereToo. This document is parsed twice by two different
// parsers, which is exactly when comment truncation bites.
func TestCommentsAreRefusedHereToo(t *testing.T) {
	p := newSPKeyPair(t)
	doc := signRequest(t, p, "_req-1")
	withComment := strings.Replace(doc, "https://sp.test</", "https://sp.test<!---->.evil.test</", 1)
	if withComment == doc {
		t.Skip("could not place a comment in the generated document")
	}
	if err := VerifyEmbeddedSignature([]byte(withComment), p.certPEM, "AuthnRequest", "_req-1"); err == nil {
		t.Fatal("a document containing an XML comment was accepted")
	}
}
