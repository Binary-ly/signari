package saml

import (
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// `signari saml signing` chooses what is signed, and until 2.05 nothing read
// the choice: every response signed the assertion and only the assertion,
// whatever the provider was set to. A provider that requires a signed Response
// rejected every sign-in, and one set to verify only the Response was still
// sent a signed assertion it might not check the way it was configured to.

// xmlsec1Verify checks the signature that the XPath selects, against the
// certificate as a service provider holds it.
func xmlsec1Verify(t *testing.T, doc string, certDER []byte, xpath string) (string, bool) {
	t.Helper()
	bin, err := exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("xmlsec1 not installed; it is the independent check")
	}
	dir := t.TempDir()
	docPath := filepath.Join(dir, "response.xml")
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(docPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "--verify", "--trusted-pem", certPath,
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:Response",
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
		"--node-xpath", xpath, docPath).CombinedOutput()
	return string(out), err == nil
}

const (
	responseSignature  = "/*/*[local-name()='Signature']"
	assertionSignature = "//*[local-name()='Assertion']/*[local-name()='Signature']"
)

func TestTheResponseIsSignedWhenAsked(t *testing.T) {
	key, certDER := testSigner(t)
	in := testInput()
	in.SignResponse = true
	out, err := BuildResponse(in, "kid-1", key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out, "<ds:Signature "); n != 2 {
		t.Fatalf("%d signatures, want 2: the assertion's and the Response's", n)
	}
	// After the Response's own Issuer, as StatusResponseType orders it.
	if !strings.Contains(out, `<saml:Issuer>https://auth.example.com/saml</saml:Issuer><ds:Signature `) ||
		strings.Index(out, "<ds:Signature ") > strings.Index(out, "<samlp:Status>") {
		t.Error("the Response's signature does not sit between its Issuer and its Status")
	}
	if got, ok := xmlsec1Verify(t, out, certDER, responseSignature); !ok {
		t.Fatalf("xmlsec1 rejected the Response signature:\n%s\n---\n%s", got, out)
	}
	if got, ok := xmlsec1Verify(t, out, certDER, assertionSignature); !ok {
		t.Fatalf("xmlsec1 rejected the assertion signature inside a signed Response:\n%s", got)
	}

	// It covers the Response: a changed Destination fails it.
	tampered := strings.Replace(out, `Destination="https://sp.example.com/acs"`,
		`Destination="https://evil.example/acs"`, 1)
	if tampered == out {
		t.Fatal("the fixture carries no Destination to change")
	}
	if _, ok := xmlsec1Verify(t, tampered, certDER, responseSignature); ok {
		t.Error("xmlsec1 accepted a Response whose Destination was changed after signing")
	}
}

func TestAResponseMayCarryTheOnlySignature(t *testing.T) {
	key, certDER := testSigner(t)
	in := testInput()
	in.UnsignedAssertion, in.SignResponse = true, true
	out, err := BuildResponse(in, "kid-1", key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out, "<ds:Signature "); n != 1 {
		t.Fatalf("%d signatures, want 1, the Response's", n)
	}
	if got, ok := xmlsec1Verify(t, out, certDER, responseSignature); !ok {
		t.Fatalf("xmlsec1 rejected the Response signature:\n%s", got)
	}
	// The Response signature covers the assertion it carries.
	tampered := strings.Replace(out, "abc-opaque-identifier", "admin-opaque-identifer", 1)
	if _, ok := xmlsec1Verify(t, tampered, certDER, responseSignature); ok {
		t.Error("xmlsec1 accepted a Response whose assertion's NameID was changed")
	}

	in.SignResponse = false
	if _, err := BuildResponse(in, "kid-1", key, certDER); err == nil {
		t.Error("a response signing nothing was built")
	}
}

// Sign, encrypt, sign: the Response signature is over the ciphertext as sent.
func TestASignedResponseCoversItsEncryptedAssertion(t *testing.T) {
	key, certDER := testSigner(t)
	sp := newSPKeyPair(t)
	in := testInput()
	in.SignResponse = true
	in.EncryptionCert = sp.certPEM
	out, err := BuildResponse(in, "kid-1", key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "EncryptedAssertion") || strings.Contains(out, "abc-opaque-identifier") {
		t.Fatal("the assertion is not encrypted, so this proves nothing")
	}
	if got, ok := xmlsec1Verify(t, out, certDER, responseSignature); !ok {
		t.Fatalf("xmlsec1 rejected the signature over an encrypted assertion:\n%s", got)
	}
}

func TestASignedResponseValidatesAgainstTheOfficialSchema(t *testing.T) {
	bin, err := exec.LookPath("xmllint")
	if err != nil {
		t.Skip("xmllint not installed")
	}
	key, certDER := testSigner(t)
	in := testInput()
	in.SignResponse = true
	out, err := BuildResponse(in, "kid-1", key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	docPath := filepath.Join(t.TempDir(), "response.xml")
	if err := os.WriteFile(docPath, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	schema, err := filepath.Abs("testdata/xsd/saml-schema-protocol-2.0.xsd")
	if err != nil {
		t.Fatal(err)
	}
	if combined, err := exec.Command(bin, "--noout", "--schema", schema, docPath).CombinedOutput(); err != nil {
		t.Fatalf("a signed Response does not validate against the protocol schema:\n%s", combined)
	}
}
