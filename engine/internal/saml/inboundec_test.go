package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// ecSender is a service provider whose signing key is P-256.
type ecSender struct {
	key     *ecdsa.PrivateKey
	certDER []byte
	certPEM string
}

func newECSender(t *testing.T) ecSender {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _, err := selfSign("https://sp.example.test", "sp-ec", key)
	if err != nil {
		t.Fatal(err)
	}
	return ecSender{key, der, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

const ecRequestTemplate = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_ec-request" Version="2.0" IssueInstant="2026-10-20T10:00:00Z"><saml:Issuer>https://sp.example.test</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/><ds:Reference URI="#_ec-request"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data/></ds:KeyInfo></ds:Signature></samlp:AuthnRequest>`

// xmlsec1Sign has xmlsec1 sign the request template with the sender's key, as
// a service provider built on it would.
func xmlsec1Sign(t *testing.T, s ecSender) string {
	t.Helper()
	bin, err := exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("xmlsec1 not installed; it is the independent signer")
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(s.key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath, certPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem")
	tmplPath, outPath := filepath.Join(dir, "request.xml"), filepath.Join(dir, "signed.xml")
	for p, b := range map[string][]byte{
		keyPath:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		certPath: []byte(s.certPEM), tmplPath: []byte(ecRequestTemplate),
	} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command(bin, "--sign", "--lax-key-search", "--privkey-pem", keyPath+","+certPath,
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest",
		"--output", outPath, tmplPath).CombinedOutput(); err != nil {
		t.Fatalf("xmlsec1 could not sign: %s", out)
	}
	signed, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func parseDoc(t *testing.T, s string) *etree.Document {
	t.Helper()
	d := etree.NewDocument()
	if err := d.ReadFromString(s); err != nil {
		t.Fatal(err)
	}
	return d
}

// A request a P-256 service provider signed with xmlsec1 verifies (3.36), and
// still fails once its content is edited. It used to fail as a bad signature:
// goxmldsig checks ECDSA as DER and the request carried r||s.
func TestAnXmlsec1SignedECDSARequestVerifies(t *testing.T) {
	s := newECSender(t)
	signed := xmlsec1Sign(t, s)
	d := parseDoc(t, signed)
	if _, err := verifySignedElement(d, d.Root(), s.certPEM, "AuthnRequest", "_ec-request"); err != nil {
		t.Fatalf("an xmlsec1-signed ECDSA request was refused: %v", err)
	}
	tampered := strings.Replace(signed, "https://sp.example.test</saml:Issuer>", "https://attacker.test</saml:Issuer>", 1)
	if tampered == signed {
		t.Fatal("the fixture has no Issuer to edit; this proves nothing")
	}
	d = parseDoc(t, tampered)
	if _, err := verifySignedElement(d, d.Root(), s.certPEM, "AuthnRequest", "_ec-request"); err == nil {
		t.Error("an edited ECDSA request verified")
	}
	// The key the request names must be the kind the certificate holds.
	rsaCert := newUpstream(t).certPEM
	d = parseDoc(t, signed)
	if _, err := verifySignedElement(d, d.Root(), rsaCert, "AuthnRequest", "_ec-request"); err == nil ||
		!strings.Contains(err.Error(), "P-256") {
		t.Errorf("an ECDSA request against an RSA certificate: %v", err)
	}
}

// An ECDSA value in DER, what a sender that skipped the conversion sends, is
// refused by name, as xmlsec1 refuses it.
func TestADEREncodedECDSARequestIsRefused(t *testing.T) {
	s := newECSender(t)
	d := parseDoc(t, ecRequestTemplate)
	root := d.Root()
	root.RemoveChild(root.SelectElement("Signature"))
	ctx, err := dsig.NewSigningContext(s.key, [][]byte{s.certDER})
	if err != nil {
		t.Fatal(err)
	}
	ctx.IdAttribute, ctx.Prefix = "ID", "ds"
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.ECDSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	signedEl, err := ctx.SignEnveloped(root)
	if err != nil {
		t.Fatal(err)
	}
	back := reparse(t, signedEl)
	_, err = verifySignedElement(back, back.Root(), s.certPEM, "AuthnRequest", "_ec-request")
	if err == nil || !strings.Contains(err.Error(), "DER") {
		t.Errorf("a DER-encoded ECDSA signature: %v", err)
	}
}

// A P-256 sender's redirect-binding signature verifies (3.36); it was refused
// as "not RSA". Edited, or checked against an RSA certificate, it is refused.
func TestAnECDSARedirectSignatureVerifies(t *testing.T) {
	s := newECSender(t)
	query, err := SignRedirectQuery("SAMLRequest", "PHNhbWw+", "rs", s.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRedirectSignature(query, s.certPEM, "SAMLRequest"); err != nil {
		t.Fatalf("an ECDSA redirect signature was refused: %v", err)
	}
	if err := VerifyRedirectSignature(strings.Replace(query, "RelayState=rs", "RelayState=rt", 1),
		s.certPEM, "SAMLRequest"); err == nil {
		t.Error("an edited RelayState verified")
	}
	if err := VerifyRedirectSignature(query, newUpstream(t).certPEM, "SAMLRequest"); err == nil ||
		!strings.Contains(err.Error(), "P-256") {
		t.Errorf("an ECDSA SigAlg against an RSA certificate: %v", err)
	}
}
