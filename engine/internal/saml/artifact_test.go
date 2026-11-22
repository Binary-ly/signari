package saml

import (
	"bytes"
	"crypto"
	"crypto/sha1" // #nosec G505 -- checking the SourceID, which is SHA-1 by definition
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

func TestAnArtifactNamesItsIssuerAndNothingGuessable(t *testing.T) {
	a, handle, err := NewArtifact("https://auth.example.com/saml")
	if err != nil {
		t.Fatal(err)
	}
	index, source, got, err := ParseArtifact(a)
	if err != nil {
		t.Fatal(err)
	}
	want := sha1.Sum([]byte("https://auth.example.com/saml")) // #nosec G401
	if index != ArtifactIndex || !bytes.Equal(source, want[:]) || !bytes.Equal(got, handle) || len(handle) != 20 {
		t.Errorf("index %d, source %x, handle %x", index, source, got)
	}
	b, other, _ := NewArtifact("https://auth.example.com/saml")
	if a == b || bytes.Equal(handle, other) {
		t.Error("two artifacts are the same")
	}
	raw, _ := base64.StdEncoding.DecodeString(a)
	for name, bad := range map[string]string{
		"not base64":   "!!!",
		"short":        base64.StdEncoding.EncodeToString(raw[:43]),
		"another type": base64.StdEncoding.EncodeToString(append([]byte{0, 1}, raw[2:]...)),
	} {
		if _, _, _, err := ParseArtifact(bad); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

// signedResolve is what a service provider sends: an ArtifactResolve signed with
// its key, in a SOAP envelope.
func signedResolve(t *testing.T, key crypto.Signer, certDER []byte, issuer, artifact string) string {
	t.Helper()
	doc := etree.NewDocument()
	el := doc.CreateElement("samlp:ArtifactResolve")
	el.CreateAttr("xmlns:samlp", nsProtocol)
	el.CreateAttr("xmlns:saml", nsAssertion)
	el.CreateAttr("ID", "_resolve1")
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))
	el.CreateElement("saml:Issuer").SetText(issuer)
	el.CreateElement("samlp:Artifact").SetText(artifact)
	if key != nil {
		signed, err := signElement(el, key, certDER)
		if err != nil {
			t.Fatal(err)
		}
		if err := moveSignatureAfterIssuer(signed); err != nil {
			t.Fatal(err)
		}
		doc.SetRoot(signed)
	}
	out, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return SOAPEnvelope(out)
}

func certPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAnArtifactResolveIsReadAndItsSignatureChecked(t *testing.T) {
	spKey, spCert := testSigner(t)
	_, otherCert := testSigner(t)
	artifact, _, err := NewArtifact("https://auth.example.com/saml")
	if err != nil {
		t.Fatal(err)
	}
	body := signedResolve(t, spKey, spCert, "https://sp.example.com/metadata", artifact)
	r, err := ReadArtifactResolve([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "_resolve1" || r.Issuer != "https://sp.example.com/metadata" || r.Artifact != artifact {
		t.Errorf("read %+v", r)
	}
	if err := r.VerifySignature(certPEM(spCert)); err != nil {
		t.Errorf("the provider's own signature: %v", err)
	}
	if err := r.VerifySignature(certPEM(otherCert)); err == nil {
		t.Error("a signature verified against another provider's certificate")
	}
	if err := r.VerifySignature(""); err == nil {
		t.Error("a provider with no certificate was taken at its word")
	}

	// The artifact asked for is the one signed.
	other, _, _ := NewArtifact("https://auth.example.com/saml")
	swapped := strings.Replace(body, artifact, other, 1)
	if r, err := ReadArtifactResolve([]byte(swapped)); err != nil || r.VerifySignature(certPEM(spCert)) == nil {
		t.Errorf("an artifact changed after signing verified: %v", err)
	}
	unsigned := signedResolve(t, nil, nil, "https://sp.example.com/metadata", artifact)
	if r, err := ReadArtifactResolve([]byte(unsigned)); err != nil || r.VerifySignature(certPEM(spCert)) == nil {
		t.Errorf("an unsigned ArtifactResolve verified: %v", err)
	}

	for name, bad := range map[string]string{
		"not SOAP":   strings.Replace(body, nsSOAP11, "urn:other", 1),
		"no issuer":  strings.Replace(body, "https://sp.example.com/metadata", "", 1),
		"a DOCTYPE":  `<!DOCTYPE x>` + body,
		"two bodies": strings.Replace(body, "</soap11:Body>", "</soap11:Body><soap11:Body/>", 1),
		// The signed element comes back canonical, its namespace declared on the Issuer.
		"an Issuer of another format": strings.Replace(body, "<saml:Issuer ",
			`<saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" `, 1),
	} {
		if _, err := ReadArtifactResolve([]byte(bad)); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

// xmlsec1VerifyAt checks the signature the XPath selects, knowing the
// ArtifactResponse's ID as well as the Response's and the Assertion's.
func xmlsec1VerifyAt(t *testing.T, doc string, certDER []byte, xpath string) (string, bool) {
	t.Helper()
	bin, err := exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("xmlsec1 not installed; it is the independent check")
	}
	dir := t.TempDir()
	docPath, certPath := filepath.Join(dir, "doc.xml"), filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(docPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte(certPEM(certDER)), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "--verify", "--trusted-pem", certPath,
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:ArtifactResponse",
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:Response",
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
		"--node-xpath", xpath, docPath).CombinedOutput()
	return string(out), err == nil
}

// The response comes back whole inside a signed ArtifactResponse: both the
// ArtifactResponse's signature and the assertion's own verify, independently.
func TestAnArtifactResponseCarriesTheResponseSigned(t *testing.T) {
	key, certDER := testSigner(t)
	inner, err := BuildResponse(testInput(), "kid-1", key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	out, err := BuildArtifactResponse(ArtifactResponseInput{Issuer: "https://auth.example.com/saml",
		InResponseTo: "_resolve1", Now: time.Now()}, inner, key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `InResponseTo="_resolve1"`) || !strings.Contains(out, StatusSuccess) ||
		!strings.Contains(out, "<samlp:Response ") {
		t.Fatalf("the answer is missing something:\n%s", out)
	}
	if !strings.Contains(out, `<saml:Issuer>https://auth.example.com/saml</saml:Issuer><ds:Signature `) {
		t.Error("the ArtifactResponse's signature does not follow its Issuer")
	}
	if got, ok := xmlsec1VerifyAt(t, out, certDER,
		"//*[local-name()='ArtifactResponse']/*[local-name()='Signature']"); !ok {
		t.Fatalf("xmlsec1 rejected the ArtifactResponse's signature:\n%s\n---\n%s", got, out)
	}
	if got, ok := xmlsec1VerifyAt(t, out, certDER,
		"//*[local-name()='Assertion']/*[local-name()='Signature']"); !ok {
		t.Fatalf("xmlsec1 rejected the assertion's signature inside it:\n%s", got)
	}
	tampered := strings.Replace(out, "abc-opaque-identifier", "someone-else", 1)
	if _, ok := xmlsec1VerifyAt(t, tampered, certDER,
		"//*[local-name()='ArtifactResponse']/*[local-name()='Signature']"); ok {
		t.Error("the ArtifactResponse's signature does not cover the response inside it")
	}
}

// An artifact that names nothing is still answered Success, with no message.
func TestAnEmptyArtifactResponseIsStillSuccess(t *testing.T) {
	key, certDER := testSigner(t)
	out, err := BuildArtifactResponse(ArtifactResponseInput{Issuer: "https://auth.example.com/saml",
		InResponseTo: "_resolve1", Now: time.Now()}, "", key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, StatusSuccess) || strings.Contains(out, "<samlp:Response ") {
		t.Errorf("an empty answer:\n%s", out)
	}
	if got, ok := xmlsec1VerifyAt(t, out, certDER,
		"//*[local-name()='ArtifactResponse']/*[local-name()='Signature']"); !ok {
		t.Errorf("xmlsec1 rejected the empty answer's signature:\n%s", got)
	}
}

// The binding a request names is the one its response goes by: to the URL it
// names, which must be registered for that binding, or to one registered for it.
func TestARequestIsAnsweredByTheBindingItNames(t *testing.T) {
	p := testProvider()
	p.ACSURLs = append(p.ACSURLs, ACSURL{URL: "https://sp.example.com/artifact", Binding: "HTTP-Artifact"})
	validate := func(url, binding string) (*Validated, error) {
		r := testRequest()
		r.AssertionConsumerServiceURL, r.ProtocolBinding = url, binding
		return ValidateAuthnRequest(r, p, ssoEndpoint, time.Now())
	}
	if v, err := validate("https://sp.example.com/artifact", BindingArtifact); err != nil ||
		v.Binding != "HTTP-Artifact" {
		t.Errorf("the artifact URL by artifact: %+v, %v", v, err)
	}
	if v, err := validate("", BindingArtifact); err != nil || v.ACSURL != "https://sp.example.com/artifact" {
		t.Errorf("by artifact with no URL named: %+v, %v", v, err)
	}
	if v, err := validate("", BindingPOST); err != nil || v.ACSURL != "https://sp.example.com/acs" {
		t.Errorf("by POST with no URL named: %+v, %v", v, err)
	}
	if v, err := validate("https://sp.example.com/artifact", ""); err != nil || v.Binding != "HTTP-Artifact" {
		t.Errorf("the artifact URL with no binding named: %+v, %v", v, err)
	}
	for _, c := range [][2]string{
		{"https://sp.example.com/artifact", BindingPOST},
		{"https://sp.example.com/acs", BindingArtifact},
		{"https://sp.example.com/acs", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"},
	} {
		if _, err := validate(c[0], c[1]); err == nil {
			t.Errorf("%s by %s was answered", c[0], c[1])
		}
	}
	if _, err := ValidateAuthnRequest(func() *AuthnRequest {
		r := testRequest()
		r.ProtocolBinding = BindingArtifact
		return r
	}(), testProvider(), ssoEndpoint, time.Now()); err == nil {
		t.Error("a provider with no artifact URL was answered by artifact")
	}
}

func TestTheMetadataNamesTheArtifactResolutionService(t *testing.T) {
	_, certDER := testSigner(t)
	doc, err := Metadata(MetadataInput{EntityID: "https://auth.example.com/saml",
		SSOURL: "https://auth.example.com/saml/sso", SLOURL: "https://auth.example.com/saml/slo",
		ArtifactURL: "https://auth.example.com/saml/artifact", Certificates: [][]byte{certDER}})
	if err != nil {
		t.Fatal(err)
	}
	ars := strings.Index(doc, "<md:ArtifactResolutionService")
	if ars < 0 || !strings.Contains(doc, `Location="https://auth.example.com/saml/artifact"`) ||
		!strings.Contains(doc, `index="0"`) {
		t.Fatalf("no artifact resolution service:\n%s", doc)
	}
	if ars > strings.Index(doc, "<md:SingleLogoutService") || ars < strings.LastIndex(doc, "</md:KeyDescriptor>") {
		t.Error("the artifact resolution service is not between the keys and the logout services")
	}
}
