package saml

import (
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

// verifySAML11 asks xmlsec1 about an assertion, which names its id in an attribute of
// its own.
func verifySAML11(t *testing.T, doc string, certDER []byte) (string, bool) {
	t.Helper()
	bin, err := exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("xmlsec1 not installed; it is the independent check")
	}
	dir := t.TempDir()
	docPath, certPath := filepath.Join(dir, "assertion.xml"), filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(docPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "--verify", "--trusted-pem", certPath,
		"--id-attr:AssertionID", "urn:oasis:names:tc:SAML:1.0:assertion:Assertion", docPath).CombinedOutput()
	return string(out), err == nil
}

// The signature names the AssertionID, and covers what it should: a name changed after
// signing is refused by an implementation that is not this one.
func TestASAML11TokenVerifiesInXmlsec1(t *testing.T) {
	key, certDER := testSigner(t)
	doc, err := BuildSAML11Assertion(testInput(), "kid", key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	if res, ok := verifySAML11(t, doc, certDER); !ok {
		t.Fatalf("xmlsec1 refused the token: %s\n%s", res, doc)
	}
	tampered := strings.Replace(doc, "abc-opaque-identifier", "somebody-else", 1)
	if tampered == doc {
		t.Fatal("nothing changed")
	}
	if res, ok := verifySAML11(t, tampered, certDER); ok {
		t.Fatalf("xmlsec1 took a token changed after signing: %s", res)
	}
}

// Everything a relying party reads, in the places the schema puts them.
func TestASAML11TokenSaysWhatARelyingPartyReads(t *testing.T) {
	key, certDER := testSigner(t)
	in := testInput()
	raw, err := BuildSAML11Assertion(in, "kid", key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(raw); err != nil {
		t.Fatal(err)
	}
	a := doc.Root()
	if a.Space != "saml" || a.SelectAttrValue("xmlns:saml", "") != nsAssertion11 {
		t.Fatalf("the root is %s in %q", a.Tag, a.SelectAttrValue("xmlns:saml", ""))
	}
	for name, want := range map[string]string{"MajorVersion": "1", "MinorVersion": "1", "Issuer": in.Issuer} {
		if got := a.SelectAttrValue(name, ""); got != want {
			t.Errorf("%s is %q", name, got)
		}
	}
	if id := a.SelectAttrValue("AssertionID", ""); !strings.HasPrefix(id, "_") {
		t.Errorf("the id %q is not an xsd:ID", id)
	}

	// Signature last, which is where this schema has it, and the order of the rest.
	var order []string
	for _, c := range a.ChildElements() {
		order = append(order, c.Tag)
	}
	if got := strings.Join(order, " "); got != "Conditions AuthenticationStatement AttributeStatement Signature" {
		t.Errorf("the children run %s", got)
	}

	cond := a.SelectElement("Conditions")
	if got := cond.FindElement("AudienceRestrictionCondition/Audience"); got == nil || got.Text() != in.Audience {
		t.Errorf("the audience is %v", got)
	}
	notAfter, err := time.Parse(time.RFC3339, cond.SelectAttrValue("NotOnOrAfter", ""))
	if err != nil || notAfter.After(in.Now.Add(in.Lifetime)) || notAfter.Before(in.Now.Add(in.Lifetime-time.Minute)) {
		t.Errorf("it expires at %v (%v)", notAfter, err)
	}

	as := a.SelectElement("AuthenticationStatement")
	if got := as.SelectAttrValue("AuthenticationMethod", ""); got != authMethodPassword {
		t.Errorf("the method is %q", got)
	}
	if got := as.SelectAttrValue("AuthenticationInstant", ""); got != in.Subject.AuthnInstant.UTC().Format(time.RFC3339) {
		t.Errorf("the instant is %q", got)
	}

	// Each statement names the person: there is no subject of the assertion.
	for _, statement := range []string{"AuthenticationStatement", "AttributeStatement"} {
		s := a.SelectElement(statement).SelectElement("Subject")
		if s == nil {
			t.Fatalf("%s names nobody", statement)
		}
		id := s.SelectElement("NameIdentifier")
		if id == nil || id.Text() != in.Subject.NameID || id.SelectAttrValue("Format", "") != in.Subject.NameIDFormat {
			t.Errorf("%s names %v", statement, id)
		}
		if got := s.FindElement("SubjectConfirmation/ConfirmationMethod"); got == nil || got.Text() != confirmationBearer11 {
			t.Errorf("%s confirms by %v", statement, got)
		}
	}
}

// The schema wants at least one attribute in a statement, so none means no statement.
func TestASAML11TokenWithNoAttributesHasNoStatementOfThem(t *testing.T) {
	key, certDER := testSigner(t)
	in := testInput()
	in.Subject.Attributes = nil
	raw, err := BuildSAML11Assertion(in, "kid", key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "AttributeStatement") {
		t.Errorf("an empty statement: %s", raw)
	}
}

func TestASAML11TokenIsRefusedWhatItCannotBe(t *testing.T) {
	key, certDER := testSigner(t)
	for name, change := range map[string]func(*ResponseInput){
		"no audience":   func(in *ResponseInput) { in.Audience = "" },
		"no lifetime":   func(in *ResponseInput) { in.Lifetime = 0 },
		"to be sealed":  func(in *ResponseInput) { in.EncryptionCert = "a certificate" },
		"left unsigned": func(in *ResponseInput) { in.UnsignedAssertion = true },
	} {
		in := testInput()
		change(&in)
		if doc, err := BuildSAML11Assertion(in, "kid", key, certDER); err == nil {
			t.Errorf("%s: built %.200s", name, doc)
		}
	}
}

// How a sign-in reads in a form older than the classes it is held in.
func TestASignInIsNamedInTheOlderForm(t *testing.T) {
	for class, want := range map[string]string{
		AuthnContextPassword:    authMethodPassword,
		AuthnContextUnspecified: authMethodUnknown,
		"":                      authMethodUnknown,
		AuthnContextMFA:         AuthnContextMFA,
	} {
		if got := authMethod11(class); got != want {
			t.Errorf("%q reads %q", class, got)
		}
	}
}

// A claim named by URL comes back whole at the relying party only when it is split
// where the relying party will join it.
func TestAnAttributeIsSplitWhereARelyingPartyJoinsIt(t *testing.T) {
	for name, want := range map[string][2]string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims", "emailaddress"},
		"department":                      {attributeNamespace11, "department"},
		"urn:oid:0.9.2342.19200300.100.1": {attributeNamespace11, "urn:oid:0.9.2342.19200300.100.1"},
		"a/b":                             {attributeNamespace11, "a/b"},
		"https://example.com/":            {attributeNamespace11, "https://example.com/"},
	} {
		if ns, local := attributeName11(name); ns != want[0] || local != want[1] {
			t.Errorf("%q split into %q and %q", name, ns, local)
		}
	}
}

// wauth asks in the classes a SAML request does, and in the two older names.
func TestAWAuthIsHeldToTheLadder(t *testing.T) {
	for wauth, want := range map[string]struct {
		rung      int
		reachable bool
	}{
		AuthnContextPassword:         {1, true},
		authMethodPassword:           {1, true},
		authMethodUnknown:            {1, true},
		AuthnContextMFA:              {2, true},
		"urn:federation:windows:not": {0, false},
	} {
		if rung, reachable := RequestedAuthType(wauth); rung != want.rung || reachable != want.reachable {
			t.Errorf("%q reached %d, %v", wauth, rung, reachable)
		}
	}
}

// A security token service, its certificates, and the endpoint a browser's request goes
// to: what an import reads.
func TestTheFederationMetadataNamesAServiceAndItsKeys(t *testing.T) {
	_, one := testSigner(t)
	_, two := testSigner(t)
	raw, err := WSFederationMetadata(WSFederationMetadataInput{
		EntityID: "https://auth.example.com/saml", Endpoint: "https://auth.example.com/wsfed",
		Certificates: [][]byte{one, two}})
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(raw); err != nil {
		t.Fatal(err)
	}
	root := doc.Root()
	if root.Tag != "EntityDescriptor" || root.SelectAttrValue("entityID", "") != "https://auth.example.com/saml" {
		t.Fatalf("the root is %s of %q", root.Tag, root.SelectAttrValue("entityID", ""))
	}
	sts := root.SelectElement("RoleDescriptor")
	if sts == nil || sts.SelectAttrValue("xsi:type", "") != "fed:SecurityTokenServiceType" ||
		sts.SelectAttrValue("protocolSupportEnumeration", "") != nsFederation {
		t.Fatalf("the role is %v", sts)
	}
	keys := sts.SelectElements("KeyDescriptor")
	if len(keys) != 2 {
		t.Fatalf("%d keys", len(keys))
	}
	for i, der := range [][]byte{one, two} {
		if got := keys[i].FindElement("KeyInfo/X509Data/X509Certificate"); got == nil || got.Text() != CertificateB64(der) ||
			keys[i].SelectAttrValue("use", "") != "signing" {
			t.Errorf("key %d is %v", i, got)
		}
	}
	var order []string
	for _, c := range sts.ChildElements() {
		order = append(order, c.Tag)
		if strings.HasSuffix(c.Tag, "Endpoint") {
			if got := c.FindElement("EndpointReference/Address"); got == nil || got.Text() != "https://auth.example.com/wsfed" {
				t.Errorf("%s is at %v", c.Tag, got)
			}
		}
	}
	// As the schema orders them, the service endpoint required and first.
	if got := strings.Join(order[2:], " "); got != "TokenTypesOffered SecurityTokenServiceEndpoint PassiveRequestorEndpoint" {
		t.Errorf("the role runs %s", got)
	}
}
