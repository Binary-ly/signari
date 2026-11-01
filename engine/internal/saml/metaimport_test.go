package saml

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// partner is a key, and the certificate that goes with it.
type partner struct {
	key  *rsa.PrivateKey
	der  []byte
	cert string // base64, as metadata carries it
	pem  string
}

func newPartner(t *testing.T) partner {
	t.Helper()
	key, der := testSigner(t)
	return partner{key, der, base64.StdEncoding.EncodeToString(der),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func spEntity(id, cert string, extra string) string {
	return fmt.Sprintf(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_%s" entityID="%s"%s>
<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true">
<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/slo-post"/>
<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.test/slo"/>
<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
<md:AssertionConsumerService index="2" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/two"/>
<md:AssertionConsumerService index="1" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/acs" isDefault="true"/>
<md:AssertionConsumerService index="3" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://sp.example.test/artifact"/>
<md:AssertionConsumerService index="4" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://sp.example.test/plain"/>
</md:SPSSODescriptor>
</md:EntityDescriptor>`, strings.ReplaceAll(id, "/", "-"), id, extra, cert)
}

func idpEntity(id string, certs ...string) string {
	var keys strings.Builder
	for _, c := range certs {
		fmt.Fprintf(&keys, `<KeyDescriptor><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></KeyDescriptor>`, c)
	}
	return fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">%s
<NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
<NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/post"/>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/>
</IDPSSODescriptor>
</EntityDescriptor>`, id, keys.String())
}

// signed signs a document's root the way an enveloped signature is made.
func signed(t *testing.T, p partner, document string) []byte {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(document); err != nil {
		t.Fatal(err)
	}
	ctx, err := dsig.NewSigningContext(p.key, [][]byte{p.der})
	if err != nil {
		t.Fatal(err)
	}
	ctx.IdAttribute = "ID"
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	out, err := ctx.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	result := etree.NewDocument()
	result.SetRoot(out)
	b, err := result.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAServiceProvidersMetadataIsRead(t *testing.T) {
	signer := newPartner(t)
	key := newPartner(t)
	const entity = "https://sp.example.test/saml"
	got, err := ReadMetadata(MetadataSource{Document: signed(t, signer, spEntity(entity, key.cert, "")),
		SignerPEM: signer.pem, EntityID: entity})
	if err != nil {
		t.Fatal(err)
	}
	if got.EntityID != entity || got.SP == nil || got.IdP != nil {
		t.Fatalf("read %+v", got)
	}
	sp := got.SP
	// The default first, whatever order the file has them in, and what cannot
	// carry an assertion left out and said so.
	if len(sp.ACSURLs) != 2 || sp.ACSURLs[0] != "https://sp.example.test/acs" || sp.ACSURLs[1] != "https://sp.example.test/two" {
		t.Errorf("ACS URLs %v", sp.ACSURLs)
	}
	if len(got.Notes) != 2 {
		t.Errorf("notes %q, wanting the artifact endpoint and the plain one", got.Notes)
	}
	if sp.SLOURL != "https://sp.example.test/slo" || sp.SLOBinding != "HTTP-Redirect" {
		t.Errorf("logout %q on %q", sp.SLOURL, sp.SLOBinding)
	}
	if !sp.WantSignedRequests || sp.NameIDFormat != "emailAddress" {
		t.Errorf("signed requests %v, NameID %q", sp.WantSignedRequests, sp.NameIDFormat)
	}
	if strings.TrimSpace(sp.SigningCertPEM) != strings.TrimSpace(key.pem) {
		t.Errorf("signing certificate %q", sp.SigningCertPEM)
	}
}

// With none marked as the default, the lowest index is, wherever the file has it.
func TestTheDefaultEndpointIsTheLowestIndexWhenNoneIsMarked(t *testing.T) {
	doc := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test">
<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<AssertionConsumerService index="7" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/seven"/>
<AssertionConsumerService index="2" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/two"/>
</SPSSODescriptor></EntityDescriptor>`
	got, err := ReadMetadata(MetadataSource{Document: []byte(doc), Unsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.SP.ACSURLs[0] != "https://sp.example.test/two" {
		t.Errorf("ACS URLs %v", got.SP.ACSURLs)
	}
}

// A provider with no certificate cannot take a logout, which is acted on only
// when signed, so its endpoint is left out and said to be.
func TestLogoutNeedsAKey(t *testing.T) {
	doc := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test">
<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.test/slo"/>
<AssertionConsumerService index="1" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/acs"/>
</SPSSODescriptor></EntityDescriptor>`
	got, err := ReadMetadata(MetadataSource{Document: []byte(doc), Unsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.SP.SLOURL != "" || len(got.Notes) != 1 {
		t.Errorf("logout %q, notes %q", got.SP.SLOURL, got.Notes)
	}
}

// A role for another version of the protocol is not the role being asked for.
func TestOnlySAML2RolesAreRead(t *testing.T) {
	doc := strings.ReplaceAll(idpEntity("https://idp.example.test", newPartner(t).cert),
		"urn:oasis:names:tc:SAML:2.0:protocol", "urn:oasis:names:tc:SAML:1.1:protocol")
	if _, err := ReadMetadata(MetadataSource{Document: []byte(doc), Unsigned: true}); err == nil ||
		!strings.Contains(err.Error(), "declares no SAML 2.0") {
		t.Errorf("a SAML 1.1 role: %v", err)
	}
}

// The key offered for encryption stands apart from the signing one: a key with
// no use stated is not offered, since a provider's two keys are kept apart here.
func TestAnEncryptionKeyIsOnlyOneStatedToBe(t *testing.T) {
	signing, encryption := newPartner(t), newPartner(t)
	tmpl := func(signingUse, second string) string {
		return fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test">
<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<KeyDescriptor%s><KeyInfo><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
%s
<AssertionConsumerService index="1" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/acs"/>
</SPSSODescriptor></EntityDescriptor>`, signingUse, signing.cert, second)
	}
	offered := fmt.Sprintf(`<KeyDescriptor use="encryption"><KeyInfo><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></KeyDescriptor>`, encryption.cert)
	got, err := ReadMetadata(MetadataSource{Document: []byte(tmpl(` use="signing"`, offered)), Unsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got.SP.EncryptionCertPEM) != strings.TrimSpace(encryption.pem) {
		t.Errorf("the key offered reads %q", got.SP.EncryptionCertPEM)
	}
	if strings.Contains(got.SP.SigningCertPEM, strings.TrimSpace(encryption.pem)) {
		t.Error("the encryption key was taken for a signing one")
	}
	if got, err = ReadMetadata(MetadataSource{Document: []byte(tmpl("", "")), Unsigned: true}); err != nil {
		t.Fatal(err)
	}
	if got.SP.EncryptionCertPEM != "" || got.SP.SigningCertPEM == "" {
		t.Errorf("a key with no stated use: signing %q, encryption %q", got.SP.SigningCertPEM, got.SP.EncryptionCertPEM)
	}
}

func TestAnIdentityProvidersMetadataIsRead(t *testing.T) {
	old, incoming := newPartner(t), newPartner(t)
	got, err := ReadMetadata(MetadataSource{Document: []byte(idpEntity("https://idp.example.test", old.cert, incoming.cert)),
		Unsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.IdP == nil || got.IdP.SSOURL != "https://idp.example.test/sso" {
		t.Fatalf("read %+v", got.IdP)
	}
	// transient cannot be held, so the next one listed is the answer.
	if got.IdP.NameIDFormat != "persistent" {
		t.Errorf("NameID %q", got.IdP.NameIDFormat)
	}
	certs, err := ParseCertificates(got.IdP.SigningCertPEM)
	if err != nil || len(certs) != 2 {
		t.Fatalf("%d certificates, %v", len(certs), err)
	}
}

// A service provider's SOAP address is read beside its browser one, needs no
// certificate of its own, and is https.
func TestAServiceProvidersSOAPLogoutIsRead(t *testing.T) {
	read := func(location string) *EntityMetadata {
		t.Helper()
		got, err := ReadMetadata(MetadataSource{Unsigned: true, Document: []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test">
<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<SingleLogoutService Binding="` + BindingSOAP + `" Location="` + location + `"/>
<AssertionConsumerService index="0" Binding="` + BindingPOST + `" Location="https://sp.example.test/acs"/>
</SPSSODescriptor></EntityDescriptor>`)})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := read("https://sp.example.test/Shibboleth.sso/SLO/SOAP"); got.SP.SOAPLogoutURL != "https://sp.example.test/Shibboleth.sso/SLO/SOAP" {
		t.Errorf("read %q", got.SP.SOAPLogoutURL)
	}
	if got := read("http://sp.example.test/slo"); got.SP.SOAPLogoutURL != "" || !strings.Contains(strings.Join(got.Notes, " "), "has to be https") {
		t.Errorf("read %q, notes %q", got.SP.SOAPLogoutURL, got.Notes)
	}
}

// A sign-out reaches an upstream as a redirect, so that is the one address kept, and
// what is left out is said.
func TestAnUpstreamsLogoutIsTheRedirectBindings(t *testing.T) {
	p := newPartner(t)
	read := func(services string) (*EntityMetadata, error) {
		document := strings.Replace(idpEntity("https://idp.example.test", p.cert),
			"<SingleSignOnService ", services+"\n<SingleSignOnService ", 1)
		return ReadMetadata(MetadataSource{Document: []byte(document), Unsigned: true})
	}
	got, err := read(`<SingleLogoutService Binding="` + BindingPOST + `" Location="https://idp.example.test/slo-post"/>
<SingleLogoutService Binding="` + BindingRedirect + `" Location="https://idp.example.test/slo"/>`)
	if err != nil {
		t.Fatal(err)
	}
	if got.IdP.SLOURL != "https://idp.example.test/slo" {
		t.Errorf("read %q", got.IdP.SLOURL)
	}
	got, err = read(`<SingleLogoutService Binding="` + BindingPOST + `" Location="https://idp.example.test/slo-post"/>`)
	if err != nil {
		t.Fatal(err)
	}
	if got.IdP.SLOURL != "" || !strings.Contains(strings.Join(got.Notes, " "), "only HTTP-POST") {
		t.Errorf("read %q, notes %q", got.IdP.SLOURL, got.Notes)
	}
}

// The row's acceptance: without a signature nothing is believed, unless the
// caller says so by name.
func TestUnsignedMetadataIsRefusedUnlessAskedForByName(t *testing.T) {
	signer := newPartner(t)
	plain := []byte(spEntity("https://sp.example.test/saml", newPartner(t).cert, ""))
	if _, err := ReadMetadata(MetadataSource{Document: plain}); !errors.Is(err, ErrMetadataTrust) {
		t.Errorf("no trust given: %v", err)
	}
	if _, err := ReadMetadata(MetadataSource{Document: plain, SignerPEM: signer.pem, Unsigned: true}); !errors.Is(err, ErrMetadataTrust) {
		t.Errorf("both given: %v", err)
	}
	if _, err := ReadMetadata(MetadataSource{Document: plain, SignerPEM: signer.pem}); !errors.Is(err, ErrMetadataUnsigned) {
		t.Errorf("unsigned with a signer named: %v", err)
	}
	if _, err := ReadMetadata(MetadataSource{Document: plain, Unsigned: true}); err != nil {
		t.Errorf("asked for by name: %v", err)
	}
}

func TestSignedMetadataIsVerifiedBeforeItIsRead(t *testing.T) {
	signer, stranger := newPartner(t), newPartner(t)
	key := newPartner(t)
	const entity = "https://sp.example.test/saml"
	good := signed(t, signer, spEntity(entity, key.cert, ""))
	if _, err := ReadMetadata(MetadataSource{Document: good, SignerPEM: stranger.pem}); err == nil {
		t.Error("a document signed by somebody else was believed")
	}
	// The classic edit: the endpoint an assertion goes to, after signing.
	tampered := strings.Replace(string(good), "https://sp.example.test/acs", "https://evil.example.test/acs", 1)
	if tampered == string(good) {
		t.Fatal("the test edited nothing")
	}
	if _, err := ReadMetadata(MetadataSource{Document: []byte(tampered), SignerPEM: signer.pem}); err == nil {
		t.Error("a document changed after signing was believed")
	}
	// A second signed copy beside the first: what is read must be what was verified.
	wrapped := strings.Replace(string(good), "</md:EntityDescriptor>",
		`<md:Extensions>`+spEntity("https://evil.example.test", key.cert, "")+`</md:Extensions></md:EntityDescriptor>`, 1)
	if _, err := ReadMetadata(MetadataSource{Document: []byte(wrapped), SignerPEM: signer.pem}); err == nil {
		t.Error("a document with something added after signing was believed")
	}
	// Two signatures, the one verified and one the parser might prefer.
	two := strings.Replace(string(good), "</md:EntityDescriptor>", `<ds:Signature/></md:EntityDescriptor>`, 1)
	if _, err := ReadMetadata(MetadataSource{Document: []byte(two), SignerPEM: signer.pem}); err == nil ||
		!strings.Contains(err.Error(), "Signature elements") {
		t.Errorf("a second Signature: %v", err)
	}
}

// What two parsers can disagree on never reaches either.
func TestMetadataIsScannedBeforeItIsParsed(t *testing.T) {
	cert := newPartner(t).cert
	for name, doc := range map[string]string{
		"a comment":   strings.Replace(spEntity("https://sp.example.test", cert, ""), "<md:NameIDFormat>", "<!-- x --><md:NameIDFormat>", 1),
		"a doctype":   `<!DOCTYPE foo [<!ENTITY a "b">]>` + spEntity("https://sp.example.test", cert, ""),
		"an AuthnReq": `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`,
		"the wrong namespace": strings.ReplaceAll(spEntity("https://sp.example.test", cert, ""),
			"urn:oasis:names:tc:SAML:2.0:metadata", "urn:example:not-metadata"),
	} {
		if _, err := ReadMetadata(MetadataSource{Document: []byte(doc), Unsigned: true}); err == nil {
			t.Errorf("%s was read", name)
		}
	}
}

// One entity by its ID, never the first.
func TestAnAggregateIsChosenFromByEntityID(t *testing.T) {
	signer := newPartner(t)
	cert := newPartner(t).cert
	inner := func(id string) string { return spEntity(id, cert, "") }
	aggregate := func(entities string) []byte {
		return signed(t, signer, `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_all">`+
			entities+`</md:EntitiesDescriptor>`)
	}
	doc := aggregate(inner("https://one.example.test") + inner("https://two.example.test"))
	got, err := ReadMetadata(MetadataSource{Document: doc, SignerPEM: signer.pem, EntityID: "https://two.example.test"})
	if err != nil || got.EntityID != "https://two.example.test" {
		t.Fatalf("read %+v, %v", got, err)
	}
	if _, err := ReadMetadata(MetadataSource{Document: doc, SignerPEM: signer.pem}); err == nil ||
		!strings.Contains(err.Error(), "describes 2 entities") {
		t.Errorf("no entity named: %v", err)
	}
	if _, err := ReadMetadata(MetadataSource{Document: doc, SignerPEM: signer.pem, EntityID: "https://three.example.test"}); err == nil {
		t.Error("an entity that is not there was found")
	}
	// A single entity is checked against the one named too.
	one := signed(t, signer, inner("https://one.example.test"))
	if _, err := ReadMetadata(MetadataSource{Document: one, SignerPEM: signer.pem, EntityID: "https://two.example.test"}); err == nil {
		t.Error("the wrong entity was taken for the one named")
	}
	// Nested groups are walked, and a name used twice is not chosen between.
	nested := aggregate(`<md:EntitiesDescriptor>` + inner("https://deep.example.test") + `</md:EntitiesDescriptor>`)
	if got, err := ReadMetadata(MetadataSource{Document: nested, SignerPEM: signer.pem, EntityID: "https://deep.example.test"}); err != nil || got.EntityID == "" {
		t.Errorf("a nested entity: %+v, %v", got, err)
	}
	twice := []byte(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">` +
		strings.ReplaceAll(inner("https://same.example.test"), `ID="_https:--same.example.test" `, ``) +
		strings.ReplaceAll(inner("https://same.example.test"), `ID="_https:--same.example.test" `, ``) + `</md:EntitiesDescriptor>`)
	if _, err := ReadMetadata(MetadataSource{Document: twice, Unsigned: true, EntityID: "https://same.example.test"}); err == nil ||
		!strings.Contains(err.Error(), "2 times") {
		t.Errorf("the same entity twice: %v", err)
	}
}

// An expired document names keys its author stopped standing behind.
func TestMetadataPastItsValidUntilIsRefused(t *testing.T) {
	signer := newPartner(t)
	cert := newPartner(t).cert
	now := time.Now()
	gone := signed(t, signer, spEntity("https://sp.example.test", cert,
		fmt.Sprintf(` validUntil="%s"`, now.Add(-time.Hour).UTC().Format(time.RFC3339))))
	if _, err := ReadMetadata(MetadataSource{Document: gone, SignerPEM: signer.pem}); err == nil ||
		!strings.Contains(err.Error(), "stopped being valid") {
		t.Errorf("past its validUntil: %v", err)
	}
	live := signed(t, signer, spEntity("https://sp.example.test", cert,
		fmt.Sprintf(` validUntil="%s"`, now.Add(time.Hour).UTC().Format(time.RFC3339))))
	if _, err := ReadMetadata(MetadataSource{Document: live, SignerPEM: signer.pem}); err != nil {
		t.Errorf("inside its validUntil: %v", err)
	}
	inner := []byte(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2001-01-01T00:00:00Z">` +
		spEntity("https://sp.example.test", cert, "") + `</md:EntitiesDescriptor>`)
	if _, err := ReadMetadata(MetadataSource{Document: inner, Unsigned: true, EntityID: "https://sp.example.test"}); err == nil {
		t.Error("a group past its validUntil was read")
	}
}

// A key that has ended cannot have made a signature worth believing, so it is
// dropped, and an upstream with none left has nothing to verify with.
func TestAnExpiredCertificateIsLeftOut(t *testing.T) {
	current, expired := newPartner(t), newPartner(t)
	end := time.Now().AddDate(30, 0, 0)
	cert, err := x509.ParseCertificate(expired.der)
	if err != nil {
		t.Fatal(err)
	}
	doc := []byte(idpEntity("https://idp.example.test", expired.cert, current.cert))
	got, err := ReadMetadata(MetadataSource{Document: doc, Unsigned: true, Now: cert.NotAfter.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if certs, _ := ParseCertificates(got.IdP.SigningCertPEM); len(certs) != 2 {
		t.Fatalf("before either ended: %d certificates", len(certs))
	}
	if _, err := ReadMetadata(MetadataSource{Document: doc, Unsigned: true, Now: end}); err == nil ||
		!strings.Contains(err.Error(), "no signing certificate") {
		t.Errorf("with every certificate ended: %v", err)
	}
}

// An upstream partway through a rotation signs with either key.
func TestEitherCertificateOfARotationVerifies(t *testing.T) {
	old, incoming, stranger := newPartner(t), newPartner(t), newPartner(t)
	const entity = "https://sp.example.test/saml"
	both := old.pem + incoming.pem
	for name, p := range map[string]partner{"the old key": old, "the incoming key": incoming} {
		if _, err := ReadMetadata(MetadataSource{Document: signed(t, p, spEntity(entity, old.cert, "")), SignerPEM: both}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ReadMetadata(MetadataSource{Document: signed(t, stranger, spEntity(entity, old.cert, "")), SignerPEM: both}); err == nil {
		t.Error("a key outside the rotation verified")
	}

	// And on the redirect binding, which signs another way.
	for name, p := range map[string]partner{"the old key": old, "the incoming key": incoming} {
		signedQuery := signRedirect(t, p.key, "abc", "")
		if err := VerifyRedirectSignature(signedQuery, both, "SAMLRequest"); err != nil {
			t.Errorf("%s on the redirect binding: %v", name, err)
		}
		if err := VerifyRedirectSignature(signedQuery, stranger.pem, "SAMLRequest"); err == nil {
			t.Errorf("%s verified against a stranger", name)
		}
	}
}

// xmlsec1 signs it, so the check is not only of what our own library wrote.
func TestMetadataSignedByXmlsec1Verifies(t *testing.T) {
	bin, err := exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("xmlsec1 not installed; it is the independent signer")
	}
	signer, key := newPartner(t), newPartner(t)
	const entity = "https://sp.example.test/saml"
	tmpl := strings.Replace(spEntity(entity, key.cert, ""), "<md:SPSSODescriptor",
		`<ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_https:--sp.example.test-saml"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate></ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:SPSSODescriptor`, 1)
	tmpl = strings.ReplaceAll(tmpl, "_https:--sp.example.test-saml", "_sp-example")
	pkcs8, err := x509.MarshalPKCS8PrivateKey(signer.key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath, certPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem")
	tmplPath, outPath := filepath.Join(dir, "in.xml"), filepath.Join(dir, "out.xml")
	for p, b := range map[string][]byte{keyPath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		certPath: []byte(signer.pem), tmplPath: []byte(tmpl)} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(bin, "--sign", "--lax-key-search", "--privkey-pem", keyPath+","+certPath,
		"--id-attr:ID", nsMetadata+":EntityDescriptor", "--output", outPath, tmplPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("xmlsec1: %v\n%s", err, out)
	}
	doc, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ReadMetadata(MetadataSource{Document: doc, SignerPEM: signer.pem, EntityID: entity}); err != nil || got.SP == nil {
		t.Fatalf("what xmlsec1 signed: %+v, %v", got, err)
	}
	if _, err := ReadMetadata(MetadataSource{Document: doc, SignerPEM: key.pem}); err == nil {
		t.Error("what xmlsec1 signed verified against another key")
	}
}

func TestMetadataIsFetchedOverHTTPSAndWithinALimit(t *testing.T) {
	ctx := context.Background()
	if _, err := FetchMetadata(ctx, http.DefaultClient, "http://sp.example.test/md"); err == nil {
		t.Error("a plaintext URL was fetched")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("<x/>"))
		case "/big":
			_, _ = w.Write(make([]byte, MetadataLimit+10))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	if got, err := FetchMetadata(ctx, srv.Client(), srv.URL+"/ok"); err != nil || string(got) != "<x/>" {
		t.Errorf("fetched %q, %v", got, err)
	}
	if _, err := FetchMetadata(ctx, srv.Client(), srv.URL+"/none"); err == nil {
		t.Error("a 404 was taken for a document")
	}
	big, err := FetchMetadata(ctx, srv.Client(), srv.URL+"/big")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMetadata(MetadataSource{Document: big, Unsigned: true}); err == nil ||
		!strings.Contains(err.Error(), "more than") {
		t.Errorf("past the limit: %v", err)
	}
}
