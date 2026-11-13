package saml

import (
	"errors"
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

// The SOAP binding, for the one thing it is used for here: telling a service provider
// of a logout with no browser to carry it (8.03).

// SOAPAction is what the binding's receivers look for in that header.
const SOAPAction = "http://www.oasis-open.org/committees/security"

// SOAPEnvelope wraps a signed message for the SOAP binding. As a string and never
// through a parser, since the signature inside is over these bytes.
func SOAPEnvelope(doc string) string {
	return `<soap11:Envelope xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/"><soap11:Body>` +
		doc + `</soap11:Body></soap11:Envelope>`
}

// ReadSOAPLogoutResponse reads what a provider answered, nil only for a
// LogoutResponse to the request named that says it succeeded. It does not check
// a signature: the provider was reached at its registered address over TLS, and
// what this decides is whether to try again, which nothing is gained by forging.
func ReadSOAPLogoutResponse(body []byte, requestID string) error {
	if err := scanForUnsafeConstructs(body); err != nil {
		return err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(body); err != nil {
		return fmt.Errorf("the answer does not parse: %w", err)
	}
	if fault := doc.FindElement("//Fault"); fault != nil {
		return fmt.Errorf("the provider answered with a SOAP fault: %.200s", strings.TrimSpace(faultText(fault)))
	}
	resp := doc.FindElement("//LogoutResponse")
	if resp == nil {
		return errors.New("the answer holds no LogoutResponse")
	}
	if got := resp.SelectAttrValue("InResponseTo", ""); got != requestID {
		return fmt.Errorf("the LogoutResponse answers %q, not this request", got)
	}
	code := resp.FindElement("./Status/StatusCode")
	if code == nil {
		return errors.New("the LogoutResponse has no status")
	}
	if status := code.SelectAttrValue("Value", ""); status != StatusSuccess {
		return fmt.Errorf("the provider answered %s", status)
	}
	return nil
}

// SOAPLogoutRequest is a LogoutRequest an identity provider sent over the SOAP binding
// to end a session with no browser: the other direction from 8.03.
type SOAPLogoutRequest struct {
	ID      string
	Request LogoutRequest
	doc     *etree.Document
	el      *etree.Element
}

// ReadSOAPLogoutRequest reads a SOAP 1.1 envelope carrying exactly one LogoutRequest.
// Nothing in it is believed until VerifySignature passes.
func ReadSOAPLogoutRequest(body []byte) (*SOAPLogoutRequest, error) {
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
	var soapBody *etree.Element
	for _, c := range env.ChildElements() {
		if c.Tag == "Body" && c.NamespaceURI() == nsSOAP11 {
			if soapBody != nil {
				return nil, errors.New("the envelope has two bodies")
			}
			soapBody = c
		}
	}
	if soapBody == nil {
		return nil, errors.New("the envelope has no body")
	}
	children := soapBody.ChildElements()
	if len(children) != 1 || children[0].Tag != "LogoutRequest" || children[0].NamespaceURI() != nsProtocol {
		return nil, errors.New("the body does not carry exactly one LogoutRequest")
	}
	el := children[0]
	id := el.SelectAttrValue("ID", "")
	if id == "" {
		return nil, errors.New("the LogoutRequest has no ID")
	}
	// The values are read from this same element, written out on its own: the one
	// whose signature VerifySignature checks.
	inner := etree.NewDocument()
	inner.SetRoot(el.Copy())
	raw, err := inner.WriteToBytes()
	if err != nil {
		return nil, err
	}
	r := &SOAPLogoutRequest{ID: id, doc: doc, el: el}
	if err := Unmarshal(raw, &r.Request); err != nil {
		return nil, err
	}
	if r.Request.ID != id {
		return nil, errors.New("the LogoutRequest's ID did not read back")
	}
	return r, nil
}

// VerifySignature checks the LogoutRequest was signed with a certificate in certPEM,
// by the rules every signed message here is held to (requestsig.go). Never optional:
// a logout acted on unsigned lets anybody sign anybody out.
func (r *SOAPLogoutRequest) VerifySignature(certPEM string) error {
	if certPEM == "" {
		return errors.New("no signing certificate is held for this provider, so its logout cannot be believed")
	}
	_, err := verifySignedElement(r.doc, r.el, certPEM, "LogoutRequest", r.ID)
	return err
}

func faultText(fault *etree.Element) string {
	if s := fault.FindElement("./faultstring"); s != nil {
		return s.Text()
	}
	return ""
}
