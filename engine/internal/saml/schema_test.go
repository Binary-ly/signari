package saml

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestResponseValidatesAgainstTheOfficialSchema.
//
// # Why this test exists
//
// It caught a bug that xmlsec1 could not: the document carried TWO identical
// <ds:Signature> elements. goxmldsig appends the signature straight onto etree's
// child slice without setting its parent, so the reordering code's RemoveChild
// silently did nothing and the insert left the same element in the list twice.
//
// The signature still verified -- xmlsec1 found a valid one and reported OK --
// so every signature-based test passed. Only schema validation noticed. A
// duplicated signature is also exactly the shape signature-wrapping attacks
// take, so strict service providers reject it outright.
//
// The schemas are the OASIS and W3C originals, vendored into testdata so this
// runs without network access.
func TestResponseValidatesAgainstTheOfficialSchema(t *testing.T) {
	bin, err := exec.LookPath("xmllint")
	if err != nil {
		t.Skip("xmllint not installed; schema validation skipped")
	}

	key, certDER := testSigner(t)
	out, err := BuildResponse(testInput(), "kid-1", key, certDER)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	docPath := filepath.Join(dir, "response.xml")
	if err := os.WriteFile(docPath, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}

	schema, err := filepath.Abs("testdata/xsd/saml-schema-protocol-2.0.xsd")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--noout", "--schema", schema, docPath)
	combined, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the response does not validate against the official SAML schema.\n"+
			"Strict service providers -- Shibboleth and anything that validates -- "+
			"will reject it, while lenient ones accept it, so this fails at one "+
			"customer and looks like their problem.\n\n%s\n---\n%s", combined, out)
	}
	if !strings.Contains(string(combined), "validates") {
		t.Fatalf("xmllint did not confirm validation:\n%s", combined)
	}
}

// TestExactlyOneSignature is the cheap version of the check above, so the
// regression is caught even where xmllint is not installed.
func TestExactlyOneSignature(t *testing.T) {
	key, certDER := testSigner(t)
	out, err := BuildResponse(testInput(), "kid-1", key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out, "<ds:Signature "); n != 1 {
		t.Fatalf("the document contains %d Signature elements, want exactly 1. "+
			"More than one still verifies, so no signature test notices, and it is "+
			"the shape a signature-wrapping attack takes.", n)
	}
	// And it must sit between Issuer and Subject, where the schema requires it.
	iIssuer := strings.Index(out, "<saml:Issuer>https://auth.example.com/saml</saml:Issuer><ds:Signature ")
	if iIssuer < 0 {
		t.Error("the signature does not immediately follow the assertion's Issuer; " +
			"the schema fixes this order and strict providers enforce it")
	}
}

// TestLogoutDocumentsValidateAgainstTheOfficialSchema.
//
// StatusResponseType and RequestAbstractType fix their child order the same way
// AssertionType does, and these documents go through the same signature
// repositioning -- so they need the same independent check rather than an
// assumption that the fix generalised.
func TestLogoutDocumentsValidateAgainstTheOfficialSchema(t *testing.T) {
	bin, err := exec.LookPath("xmllint")
	if err != nil {
		t.Skip("xmllint not installed")
	}
	key, certDER := testSigner(t)

	req, err := BuildLogoutRequest(LogoutRequestInput{
		Issuer: "https://auth.example.com/saml", Destination: "https://sp.example.com/slo",
		NameID: "opaque", NameIDFormat: NameIDFormatPersistent, SessionIndex: "s1",
		Now: time.Now(),
	}, key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := BuildLogoutResponse(LogoutResponseInput{
		Issuer: "https://auth.example.com/saml", Destination: "https://sp.example.com/slo",
		InResponse: "_lo1", Now: time.Now(),
	}, key, certDER)
	if err != nil {
		t.Fatal(err)
	}

	schema, err := filepath.Abs("testdata/xsd/saml-schema-protocol-2.0.xsd")
	if err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{"LogoutRequest": req, "LogoutResponse": resp} {
		path := filepath.Join(t.TempDir(), name+".xml")
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(bin, "--noout", "--schema", schema, path).CombinedOutput()
		if err != nil {
			t.Errorf("%s does not validate against the official schema:\n%s\n---\n%s",
				name, out, doc)
		}
	}
}
