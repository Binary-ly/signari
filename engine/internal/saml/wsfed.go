package saml

import (
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// What WS-Federation needs of this package and SAML 2.0 does not: a token in the
// older form some relying parties were built against, and metadata naming a security
// token service rather than an identity provider.
//
// The element and attribute names here were read from the two OASIS schemas, not
// remembered: oasis-sstc-saml-schema-assertion-1.1.xsd, and ws-federation.xsd.

const (
	nsAssertion11 = "urn:oasis:names:tc:SAML:1.0:assertion"
	nsFederation  = "http://docs.oasis-open.org/wsfed/federation/200706"
	nsAddressing  = "http://www.w3.org/2005/08/addressing"
	nsXSI         = "http://www.w3.org/2001/XMLSchema-instance"

	// WSFedSAML2 and WSFedSAML11 are the values of a provider's WSFedSAMLVersion.
	WSFedSAML2  = "2.0"
	WSFedSAML11 = "1.1"

	tokenTypeSAML2  = "urn:oasis:names:tc:SAML:2.0:assertion"
	tokenTypeSAML11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1"

	confirmationBearer11 = "urn:oasis:names:tc:SAML:1.0:cm:bearer"
	authMethodPassword   = "urn:oasis:names:tc:SAML:1.0:am:password"
	authMethodUnknown    = "urn:oasis:names:tc:SAML:1.0:am:unspecified"

	// attributeNamespace11 is where an attribute with no namespace of its own goes:
	// SAML 1.1 requires one on every attribute, where 2.0 has a single name.
	attributeNamespace11 = "http://schemas.xmlsoap.org/claims"
)

// WSFedTokenType is what an answer says it carries, for a provider's version.
func WSFedTokenType(version string) string {
	if version == WSFedSAML11 {
		return tokenTypeSAML11
	}
	return tokenTypeSAML2
}

// RequestedAuthType is the rung a session must reach to answer a wauth, and whether
// one can be reached at all. The older names for the two things a SAML 1.1 assertion
// can say of a sign-in are the same demand as the classes they became.
func RequestedAuthType(wauth string) (rung int, reachable bool) {
	switch wauth {
	case authMethodPassword:
		wauth = AuthnContextPassword
	case authMethodUnknown:
		wauth = AuthnContextUnspecified
	}
	return RequestedRung([]string{wauth}, "")
}

// BuildSAML11Assertion is the token a relying party that reads nothing newer takes:
// one signed assertion, standing alone. It is what BuildResponse's caller gets back
// in the same shape, so nothing above this package needs a second way to ask.
//
// # What it cannot say
//
// An assertion in this form has no Recipient and no InResponseTo. Both are what tie a
// SAML 2.0 assertion to one delivery and one request, and the schema has no place for
// either: the audience and the lifetime are all that bound a token here, which is the
// reason to keep the lifetime short and to choose this form only for a relying party
// that takes nothing else.
//
// Nor is it encrypted. A provider that registered an encryption certificate is refused
// rather than sent in the clear what it asked to have sealed.
func BuildSAML11Assertion(in ResponseInput, _ string, signer crypto.Signer, certDER []byte) (string, error) {
	if in.Audience == "" {
		return "", fmt.Errorf("refusing to build an assertion with no Audience: it would " +
			"be valid at every relying party, not just the one that asked")
	}
	if in.Lifetime <= 0 {
		return "", fmt.Errorf("refusing to build an assertion with no lifetime: it would never expire")
	}
	if in.EncryptionCert != "" {
		return "", fmt.Errorf("refusing to send a SAML 1.1 token to a provider with an encryption " +
			"certificate: it could only go in the clear")
	}
	if in.UnsignedAssertion {
		return "", fmt.Errorf("refusing to build an unsigned SAML 1.1 assertion: nothing goes " +
			"out around it for a signature to be on")
	}
	if _, err := SignatureMethod(signer); err != nil {
		return "", err
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	// The signature goes where the library appends it: last, which is where the 1.1
	// schema puts it (AssertionType), not after the Issuer as in 2.0.
	signed, err := signElementBy(buildAssertion11(id, in), "AssertionID", signer, certDER)
	if err != nil {
		return "", fmt.Errorf("signing the assertion: %w", err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	return doc.WriteToString()
}

func buildAssertion11(id string, in ResponseInput) *etree.Element {
	now := in.Now.UTC().Truncate(time.Second)

	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", nsAssertion11)
	a.CreateAttr("MajorVersion", "1")
	a.CreateAttr("MinorVersion", "1")
	a.CreateAttr("AssertionID", id)
	a.CreateAttr("Issuer", in.Issuer)
	a.CreateAttr("IssueInstant", now.Format(time.RFC3339))

	conditions := a.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", now.Add(-clockSkew).Format(time.RFC3339))
	conditions.CreateAttr("NotOnOrAfter", now.Add(in.Lifetime).Format(time.RFC3339))
	conditions.CreateElement("saml:AudienceRestrictionCondition").
		CreateElement("saml:Audience").SetText(in.Audience)

	as := a.CreateElement("saml:AuthenticationStatement")
	as.CreateAttr("AuthenticationMethod", authMethod11(in.Subject.AuthnContext))
	as.CreateAttr("AuthenticationInstant", in.Subject.AuthnInstant.UTC().Format(time.RFC3339))
	addSubject11(as, in.Subject)

	// There is no statement with no attributes: the schema wants at least one.
	if len(in.Subject.Attributes) > 0 {
		stmt := a.CreateElement("saml:AttributeStatement")
		addSubject11(stmt, in.Subject)
		for _, name := range sortedKeys(in.Subject.Attributes) {
			ns, local := attributeName11(name)
			attr := stmt.CreateElement("saml:Attribute")
			attr.CreateAttr("AttributeName", local)
			attr.CreateAttr("AttributeNamespace", ns)
			for _, v := range in.Subject.Attributes[name] {
				attr.CreateElement("saml:AttributeValue").SetText(v)
			}
		}
	}
	return a
}

// addSubject11 names the person inside a statement. SAML 1.1 has no subject of the
// assertion: each statement carries its own.
func addSubject11(statement *etree.Element, s Subject) {
	subject := statement.CreateElement("saml:Subject")
	nameID := subject.CreateElement("saml:NameIdentifier")
	nameID.CreateAttr("Format", s.NameIDFormat)
	nameID.SetText(s.NameID)
	subject.CreateElement("saml:SubjectConfirmation").
		CreateElement("saml:ConfirmationMethod").SetText(confirmationBearer11)
}

// authMethod11 says how the person signed in. The two classes with a 1.1 name take
// it, and any other goes as it is: the attribute is a URI, and what it says stays true.
func authMethod11(class string) string {
	switch class {
	case AuthnContextPassword:
		return authMethodPassword
	case "", AuthnContextUnspecified:
		return authMethodUnknown
	}
	return class
}

// attributeName11 splits a claim named by URL at its last slash. That is the form the
// claims these applications read are named in, and a namespace with the name appended
// is what a relying party puts back together. Anything else is a bare name.
func attributeName11(name string) (namespace, local string) {
	if at := strings.LastIndexByte(name, '/'); strings.Contains(name, "://") && at > 0 && at < len(name)-1 {
		return name[:at], name[at+1:]
	}
	return attributeNamespace11, name
}

// WSFederationMetadataInput is what a relying party is told of this server.
type WSFederationMetadataInput struct {
	// EntityID is the Issuer on every token, which is what a relying party holds a
	// token's issuer to.
	EntityID string
	// Endpoint is where sign-in and sign-out requests go.
	Endpoint string
	// Certificates, newest first, for the reason Metadata publishes more than one.
	Certificates [][]byte
}

// WSFederationMetadata renders the document a relying party imports: a security token
// service, whose signing certificates are what it pins.
//
// Not signed, for the reason Metadata gives: a relying party fetching this over HTTPS
// from our domain already has what a signature would tell it.
func WSFederationMetadata(in WSFederationMetadataInput) (string, error) {
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	ed := doc.CreateElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", nsMetadata)
	ed.CreateAttr("xmlns:ds", nsDsig)
	ed.CreateAttr("xmlns:fed", nsFederation)
	ed.CreateAttr("xmlns:wsa", nsAddressing)
	ed.CreateAttr("xmlns:xsi", nsXSI)
	ed.CreateAttr("entityID", in.EntityID)

	sts := ed.CreateElement("md:RoleDescriptor")
	sts.CreateAttr("xsi:type", "fed:SecurityTokenServiceType")
	sts.CreateAttr("protocolSupportEnumeration", nsFederation)

	for _, der := range in.Certificates {
		kd := sts.CreateElement("md:KeyDescriptor")
		kd.CreateAttr("use", "signing")
		kd.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").
			CreateElement("ds:X509Certificate").SetText(CertificateB64(der))
	}

	offered := sts.CreateElement("fed:TokenTypesOffered")
	for _, tokenType := range []string{tokenTypeSAML2, tokenTypeSAML11} {
		offered.CreateElement("fed:TokenType").CreateAttr("Uri", tokenType)
	}

	// Both, and in this order: the schema requires the first and places the second
	// after it, and it is the second that a browser's request is sent to.
	for _, role := range []string{"fed:SecurityTokenServiceEndpoint", "fed:PassiveRequestorEndpoint"} {
		sts.CreateElement(role).CreateElement("wsa:EndpointReference").
			CreateElement("wsa:Address").SetText(in.Endpoint)
	}

	doc.Indent(2)
	return doc.WriteToString()
}
