package saml

import (
	"encoding/xml"
	"errors"
	"fmt"
	"html"

	"github.com/beevik/etree"
)

// The Enhanced Client or Proxy profile, the identity provider's part (8.08,
// saml-profiles-2.0-os §4.2): a client that is not a browser brings the
// service provider's AuthnRequest here in a SOAP body, proves who the person is,
// and takes the Response back in a SOAP body addressed to the provider's PAOS
// endpoint.

// BindingPAOS is the reverse SOAP binding an ECP takes the response to the
// service provider by.
const BindingPAOS = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS"

const nsECP = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"

// ECPRequest is an AuthnRequest an ECP brought, and where in the envelope it
// was, for checking a signature over exactly what was read.
type ECPRequest struct {
	Request *AuthnRequest
	doc     *etree.Document
	el      *etree.Element
}

// ReadECPRequest reads a SOAP 1.1 envelope whose body is one AuthnRequest. The
// header blocks an ECP is to remove before sending it here (lines 789-790) are
// not read.
func ReadECPRequest(body []byte) (*ECPRequest, error) {
	if err := scanForUnsafeConstructs(body); err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(body); err != nil {
		return nil, fmt.Errorf("the request does not parse: %w", err)
	}
	env := doc.Root()
	if env == nil || env.Tag != "Envelope" || env.NamespaceURI() != nsSOAP11 {
		return nil, errors.New("the request is not a SOAP 1.1 envelope")
	}
	var bodies []*etree.Element
	for _, c := range env.ChildElements() {
		if c.Tag == "Body" && c.NamespaceURI() == nsSOAP11 {
			bodies = append(bodies, c)
		}
	}
	if len(bodies) != 1 {
		return nil, errors.New("the envelope does not have exactly one body")
	}
	children := bodies[0].ChildElements()
	if len(children) != 1 || children[0].Tag != "AuthnRequest" || children[0].NamespaceURI() != nsProtocol {
		return nil, errors.New("the body does not carry exactly one AuthnRequest")
	}
	var parsed struct {
		XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
		Body    struct {
			AuthnRequest AuthnRequest `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
		} `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	}
	if err := Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	return &ECPRequest{Request: &parsed.Body.AuthnRequest, doc: doc, el: children[0]}, nil
}

// VerifySignature checks the AuthnRequest was signed with a certificate in
// certPEM, by the rules every signed request here is held to.
func (r *ECPRequest) VerifySignature(certPEM string) error {
	if certPEM == "" {
		return errors.New("signed requests are required of this service provider and no signing " +
			"certificate is registered for it")
	}
	_, err := verifySignedElement(r.doc, r.el, certPEM, "AuthnRequest", r.Request.ID)
	return err
}

// ECPEnvelope wraps a Response for the ECP to carry to acs, with the ECP
// Response header block the identity provider "MUST" send (lines 1005-1012):
// mustUnderstand 1, the next actor, and the AssertionConsumerServiceURL the ECP
// checks against what the provider told it. As a string, never re-serialised:
// the signatures inside are over these bytes.
func ECPEnvelope(acs, response string) string {
	return `<soap11:Envelope xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ecp="` + nsECP + `">` +
		`<soap11:Header><ecp:Response soap11:mustUnderstand="1" ` +
		`soap11:actor="http://schemas.xmlsoap.org/soap/actor/next" ` +
		`AssertionConsumerServiceURL="` + html.EscapeString(acs) + `"/></soap11:Header>` +
		`<soap11:Body>` + response + `</soap11:Body></soap11:Envelope>`
}
