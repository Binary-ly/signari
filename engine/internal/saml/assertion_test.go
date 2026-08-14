package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSigner(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _, err := selfSign("https://auth.example.com", key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

func testInput() ResponseInput {
	now := time.Now()
	return ResponseInput{
		Issuer:      "https://auth.example.com/saml",
		Destination: "https://sp.example.com/acs",
		InResponse:  "_req123",
		Audience:    "https://sp.example.com/metadata",
		Lifetime:    5 * time.Minute,
		Now:         now,
		Subject: Subject{
			NameID:       "abc-opaque-identifier",
			NameIDFormat: NameIDFormatPersistent,
			SessionIndex: "sess-1",
			AuthnInstant: now,
			AuthnContext: AuthnContextPassword,
			Attributes: map[string][]string{
				"email":  {"alice@example.test"},
				"groups": {"engineering", "oncall"},
			},
		},
	}
}

// TestSignatureVerifiesWithXmlsec1 is the test this whole package is built
// around.
//
// Verifying our own signature with our own library proves only that we are
// self-consistent. xmlsec1 is the reference C implementation that most SAML
// software -- python-saml, php-saml, Shibboleth, and the tooling behind a great
// many service providers -- is built on or checked against. If it accepts the
// assertion, real service providers will.
func TestSignatureVerifiesWithXmlsec1(t *testing.T) {
	bin, err := exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("xmlsec1 not installed; this test is the independent check and is being skipped")
	}

	key, certDER := testSigner(t)
	out, err := BuildResponse(testInput(), "kid-1", key, certDER)
	if err != nil {
		t.Fatalf("BuildResponse: %v", err)
	}

	dir := t.TempDir()
	docPath := filepath.Join(dir, "response.xml")
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(docPath, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	// The certificate is passed as TRUSTED, which is precisely what a service
	// provider does: it holds a copy taken from our metadata and verifies
	// against that, with no chain to a public root involved. Passing it as an
	// untrusted certificate instead yields KEY-NOT-FOUND, which reads like a
	// signature failure and is not one.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// --id-attr tells xmlsec1 which attribute the signature Reference URI points
	// at. Without it the reference cannot be resolved and every document looks
	// broken -- which is exactly how an SP misconfiguration presents, too.
	cmd := exec.Command(bin, "--verify",
		"--trusted-pem", certPath,
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
		docPath)
	combined, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("xmlsec1 REJECTED our signature:\n%s\n---\ndocument:\n%s", combined, out)
	}
	if !strings.Contains(string(combined), "OK") {
		t.Fatalf("xmlsec1 did not report OK:\n%s", combined)
	}
	t.Logf("xmlsec1: %s", strings.TrimSpace(strings.SplitN(string(combined), "\n", 2)[0]))
}

// TestTamperedAssertionIsRejectedByXmlsec1 proves the signature covers what we
// think it covers.
//
// A signature that verifies is worth nothing if editing the identity does not
// break it -- and "signed the wrong element" is a bug that passes every
// positive test.
func TestTamperedAssertionIsRejectedByXmlsec1(t *testing.T) {
	bin, err := exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("xmlsec1 not installed")
	}

	key, certDER := testSigner(t)
	out, err := BuildResponse(testInput(), "kid-1", key, certDER)
	if err != nil {
		t.Fatal(err)
	}

	// Change who the assertion is about, leaving everything else alone.
	tampered := strings.Replace(out, "abc-opaque-identifier", "admin-opaque-identifer", 1)
	if tampered == out {
		t.Fatal("the fixture did not contain the NameID; this test proves nothing")
	}

	dir := t.TempDir()
	docPath := filepath.Join(dir, "tampered.xml")
	certPath := filepath.Join(dir, "cert.pem")
	_ = os.WriteFile(docPath, []byte(tampered), 0o600)
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600)

	cmd := exec.Command(bin, "--verify",
		"--trusted-pem", certPath,
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
		docPath)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("xmlsec1 ACCEPTED an assertion whose NameID was changed after signing:\n%s", out)
	}
}

// TestAssertionCarriesItsSafetyProperties.
//
// The signature is the part everyone gets right. These are the parts that get
// left out, each of which is a serious vulnerability on its own even when the
// signature is perfect.
func TestAssertionCarriesItsSafetyProperties(t *testing.T) {
	key, certDER := testSigner(t)
	out, err := BuildResponse(testInput(), "kid-1", key, certDER)
	if err != nil {
		t.Fatal(err)
	}

	required := []struct {
		fragment, why string
	}{
		{`<saml:Audience>https://sp.example.com/metadata</saml:Audience>`,
			"without AudienceRestriction this assertion is valid at EVERY service provider"},
		{`Recipient="https://sp.example.com/acs"`,
			"without Recipient a captured assertion can be posted to another endpoint"},
		{`InResponseTo="_req123"`,
			"without InResponseTo an assertion can be injected into a login the user never started"},
		{`NotOnOrAfter=`,
			"without an expiry the assertion is a bearer credential valid forever"},
		{`NotBefore=`,
			"Conditions must bound the start of validity too"},
		{`Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"`,
			"the confirmation method must be stated"},
		{`SessionIndex="sess-1"`,
			"without SessionIndex single logout cannot name which session to end"},
		{`<ds:Signature`, "the assertion must be signed"},
		{`<ds:X509Certificate>`, "the certificate must travel with it, or the SP cannot match its pin"},
		{`rsa-sha256`, "SHA-1 signatures are refused by modern service providers"},
	}
	for _, r := range required {
		if !strings.Contains(out, r.fragment) {
			t.Errorf("assertion is missing %s\n  %s", r.fragment, r.why)
		}
	}

	// The signature must be INSIDE the Assertion, not merely somewhere in the
	// document -- that distinction is the signature-wrapping class.
	assertionStart := strings.Index(out, "<saml:Assertion")
	sigStart := strings.Index(out, "<ds:Signature")
	if assertionStart < 0 || sigStart < assertionStart {
		t.Error("the signature is not inside the Assertion element; signing the Response " +
			"alone is what signature-wrapping attacks exploit")
	}
}

// TestRefusesToBuildAnUnsafeAssertion -- the guards are worth having because
// each missing field is silent. Nothing rejects an assertion with no Audience
// except the absence of an attacker.
func TestRefusesToBuildAnUnsafeAssertion(t *testing.T) {
	key, certDER := testSigner(t)

	cases := []struct {
		name   string
		mutate func(*ResponseInput)
	}{
		{"no audience", func(in *ResponseInput) { in.Audience = "" }},
		{"no destination", func(in *ResponseInput) { in.Destination = "" }},
		{"no lifetime", func(in *ResponseInput) { in.Lifetime = 0 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := testInput()
			c.mutate(&in)
			if _, err := BuildResponse(in, "kid-1", key, certDER); err == nil {
				t.Fatalf("built an assertion with %s", c.name)
			}
		})
	}
}

// TestIDsAreValidXsdIDs. A value starting with a digit is invalid xsd:ID:
// schema-validating service providers reject it and non-validating ones do not,
// so the deployment works everywhere except the customer who validates.
func TestIDsAreValidXsdIDs(t *testing.T) {
	for i := 0; i < 200; i++ {
		id, err := newID()
		if err != nil {
			t.Fatal(err)
		}
		if id == "" {
			t.Fatal("empty id")
		}
		c := id[0]
		if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			t.Fatalf("id %q starts with %q, which is not valid for xsd:ID", id, c)
		}
	}
	// And they must not repeat.
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id, _ := newID()
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

// TestECDSAKeyIsRefusedWithAnExplanation. An EC-signed assertion is spec-valid
// and rejected by a great deal of real SP software, which is a far worse failure
// to diagnose than being told up front.
func TestECDSAKeyIsRefusedWithAnExplanation(t *testing.T) {
	in := testInput()
	ec := ecdsaKey(t)
	_, err := BuildResponse(in, "kid-1", ec, nil)
	if err == nil {
		t.Fatal("an ECDSA key was accepted for SAML signing")
	}
	if !strings.Contains(err.Error(), "RS256") {
		t.Errorf("the error should say what to do about it; got %v", err)
	}
}

func ecdsaKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
