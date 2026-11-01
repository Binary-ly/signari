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

func faultText(fault *etree.Element) string {
	if s := fault.FindElement("./faultstring"); s != nil {
		return s.Text()
	}
	return ""
}
