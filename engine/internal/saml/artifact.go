package saml

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- the artifact's SourceID is SHA-1 by definition, an identifier and not a signature
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// The HTTP Artifact binding, for the response half of Web SSO (8.08): the browser
// carries a reference, and the service provider fetches the response from the
// artifact resolution service over SOAP.

// BindingArtifact names the binding (saml-bindings-2.0-os line 990).
const BindingArtifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"

const nsSOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"

// The type 0x0004 artifact (lines 1074-1078): TypeCode, EndpointIndex, a 20-byte
// SourceID and a 20-byte MessageHandle, base64 together.
const (
	artifactType   = 0x0004
	artifactLength = 2 + 2 + 20 + 20
)

// ArtifactIndex is the index of the one artifact resolution service published.
const ArtifactIndex = 0

// nameIDFormatEntity is the one format an ArtifactResolve's Issuer may name.
const nameIDFormatEntity = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"

// SourceID is the issuer's SHA-1, "NOT encoded into hexadecimal" (line 1062).
func SourceID(entityID string) []byte {
	sum := sha1.Sum([]byte(entityID)) // #nosec G401 -- see the import
	return sum[:]
}

// NewArtifact makes an artifact naming entityID as its issuer, and the message
// handle it carries: 20 random bytes, which "MUST be infeasible to construct or
// guess" (line 1090).
func NewArtifact(entityID string) (artifact string, handle []byte, err error) {
	handle = make([]byte, 20)
	if _, err := rand.Read(handle); err != nil {
		return "", nil, err
	}
	raw := make([]byte, 0, artifactLength)
	raw = binary.BigEndian.AppendUint16(raw, artifactType)
	raw = binary.BigEndian.AppendUint16(raw, ArtifactIndex)
	raw = append(raw, SourceID(entityID)...)
	raw = append(raw, handle...)
	return base64.StdEncoding.EncodeToString(raw), handle, nil
}

// ParseArtifact reads a type 0x0004 artifact.
func ParseArtifact(artifact string) (index uint16, sourceID, handle []byte, err error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(artifact))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("the artifact is not base64: %w", err)
	}
	if len(raw) != artifactLength {
		return 0, nil, nil, fmt.Errorf("the artifact is %d bytes, not %d", len(raw), artifactLength)
	}
	if t := binary.BigEndian.Uint16(raw); t != artifactType {
		return 0, nil, nil, fmt.Errorf("the artifact is of type 0x%04x, not 0x0004", t)
	}
	return binary.BigEndian.Uint16(raw[2:]), raw[4:24], raw[24:], nil
}

// ArtifactResolve is a service provider asking for the message an artifact names.
type ArtifactResolve struct {
	ID, Issuer, Destination, Artifact string
	IssueInstant                      time.Time
	// doc and el are the document read and the element in it, kept for checking
	// the signature over exactly what was read.
	doc *etree.Document
	el  *etree.Element
}

// ReadArtifactResolve reads a SOAP 1.1 envelope carrying one ArtifactResolve.
func ReadArtifactResolve(body []byte) (*ArtifactResolve, error) {
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
	if len(children) != 1 || children[0].Tag != "ArtifactResolve" || children[0].NamespaceURI() != nsProtocol {
		return nil, errors.New("the body does not carry exactly one ArtifactResolve")
	}
	el := children[0]
	r := &ArtifactResolve{
		ID:          el.SelectAttrValue("ID", ""),
		Destination: el.SelectAttrValue("Destination", ""),
		doc:         doc,
		el:          el,
	}
	if r.ID == "" {
		return nil, errors.New("the ArtifactResolve has no ID")
	}
	if v := el.SelectAttrValue("Version", ""); v != "2.0" {
		return nil, fmt.Errorf("the ArtifactResolve is version %q, not 2.0", v)
	}
	instant, err := time.Parse(time.RFC3339, el.SelectAttrValue("IssueInstant", ""))
	if err != nil {
		return nil, fmt.Errorf("the ArtifactResolve's IssueInstant: %w", err)
	}
	r.IssueInstant = instant
	for _, c := range el.ChildElements() {
		switch {
		case c.Tag == "Issuer" && c.NamespaceURI() == nsAssertion:
			// "the Format attribute MUST be omitted or have a value of
			// urn:oasis:names:tc:SAML:2.0:nameid-format:entity" (saml-profiles-2.0-os
			// lines 1489-1490).
			if f := c.SelectAttrValue("Format", ""); f != "" && f != nameIDFormatEntity {
				return nil, fmt.Errorf("the ArtifactResolve's Issuer has the format %q", f)
			}
			r.Issuer = strings.TrimSpace(c.Text())
		case c.Tag == "Artifact" && c.NamespaceURI() == nsProtocol:
			r.Artifact = strings.TrimSpace(c.Text())
		}
	}
	// "The <Issuer> element MUST be present" (line 1488).
	if r.Issuer == "" {
		return nil, errors.New("the ArtifactResolve names no Issuer")
	}
	if r.Artifact == "" {
		return nil, errors.New("the ArtifactResolve carries no Artifact")
	}
	return r, nil
}

// VerifySignature checks the ArtifactResolve was signed with a certificate in
// certPEM, by the rules every signed request here is held to (requestsig.go).
func (r *ArtifactResolve) VerifySignature(certPEM string) error {
	if certPEM == "" {
		return errors.New("no signing certificate is registered for this service provider, so it " +
			"cannot show the artifact was issued to it")
	}
	_, err := verifySignedElement(r.doc, r.el, certPEM, "ArtifactResolve", r.ID)
	return err
}

// ArtifactResponseInput is what an ArtifactResponse says, besides the message.
type ArtifactResponseInput struct {
	Issuer, InResponseTo string
	Now                  time.Time
}

// BuildArtifactResponse answers an ArtifactResolve in a SOAP envelope, with the
// message the artifact named, or none: "In both cases, the <Status> element MUST
// include a <StatusCode> element with the code value ...Success"
// (saml-core-2.0-os lines 2388-2390). It is signed, since "The responder MUST
// authenticate itself to the requester ... either by signing the message or
// using a binding-specific mechanism" (saml-profiles-2.0-os lines 1498-1499).
func BuildArtifactResponse(in ArtifactResponseInput, message string, signer crypto.Signer,
	certDER []byte) (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:ArtifactResponse")
	resp.CreateAttr("xmlns:samlp", nsProtocol)
	resp.CreateAttr("xmlns:saml", nsAssertion)
	resp.CreateAttr("ID", id)
	// "the <ArtifactResponse> message's InResponseTo attribute MUST contain the
	// value of the corresponding <ArtifactResolve> message's ID attribute"
	// (saml-core-2.0-os lines 2404-2405).
	resp.CreateAttr("InResponseTo", in.InResponseTo)
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", in.Now.UTC().Truncate(time.Second).Format(time.RFC3339))
	resp.CreateElement("saml:Issuer").SetText(in.Issuer)
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", StatusSuccess)
	if message != "" {
		inner := etree.NewDocument()
		if err := inner.ReadFromString(message); err != nil {
			return "", fmt.Errorf("the message the artifact names does not parse: %w", err)
		}
		resp.AddChild(inner.Root())
	}
	signed, err := signElement(resp, signer, certDER)
	if err != nil {
		return "", err
	}
	if err := moveSignatureAfterIssuer(signed); err != nil {
		return "", err
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	text, err := out.WriteToString()
	if err != nil {
		return "", err
	}
	return SOAPEnvelope(text), nil
}

// ArtifactResolveInput is what an ArtifactResolve this deployment sends says: the
// request half of Web SSO and logout by artifact, where a service provider issued the
// artifact and this deployment fetches the message from it.
type ArtifactResolveInput struct {
	Issuer, Destination, Artifact string
	Now                           time.Time
}

// BuildArtifactResolve asks a service provider for the message an artifact it issued
// names, in a SOAP envelope, and answers the request's ID, which the answer's
// InResponseTo must carry. It is signed: "The requester SHOULD authenticate itself to
// the responder, either by signing the <ArtifactResolve> message or using any other
// binding-supported mechanism" (saml-profiles-2.0-os lines 1471-1472).
func BuildArtifactResolve(in ArtifactResolveInput, signer crypto.Signer, certDER []byte) (envelope, id string, err error) {
	if id, err = newID(); err != nil {
		return "", "", err
	}
	doc := etree.NewDocument()
	req := doc.CreateElement("samlp:ArtifactResolve")
	req.CreateAttr("xmlns:samlp", nsProtocol)
	req.CreateAttr("xmlns:saml", nsAssertion)
	req.CreateAttr("ID", id)
	req.CreateAttr("Version", "2.0")
	req.CreateAttr("IssueInstant", in.Now.UTC().Truncate(time.Second).Format(time.RFC3339))
	req.CreateAttr("Destination", in.Destination)
	// "The <Issuer> element MUST be present and MUST contain the unique identifier of
	// the requesting entity" (lines 1488-1489).
	req.CreateElement("saml:Issuer").SetText(in.Issuer)
	req.CreateElement("samlp:Artifact").SetText(in.Artifact)
	signed, err := signElement(req, signer, certDER)
	if err != nil {
		return "", "", err
	}
	if err := moveSignatureAfterIssuer(signed); err != nil {
		return "", "", err
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	text, err := out.WriteToString()
	if err != nil {
		return "", "", err
	}
	return SOAPEnvelope(text), id, nil
}

// ArtifactResponse is a service provider's answer to an ArtifactResolve this
// deployment sent.
type ArtifactResponse struct {
	ID, InResponseTo, Issuer, StatusCode string
	// Message is the message the artifact named, lifted out as a document of its own,
	// or nil when the provider answered with none, which it does for an artifact it
	// did not issue, already gave out, or will not give to this deployment
	// (saml-bindings-2.0-os lines 1180-1184).
	Message []byte
}

// ReadArtifactResponse reads a SOAP 1.1 envelope carrying one ArtifactResponse.
//
// It checks no signature on the answer. "The responder MUST authenticate itself to
// the requester, either by signing the <ArtifactResponse> or using any other
// binding-supported mechanism" (saml-profiles-2.0-os lines 1482-1483), and the
// mechanism here is the binding's: the answer is read only from the provider's
// registered https address, its certificate verified, as the SOAP logout answers
// are. A provider signing its answer around a request it also signed puts two
// signatures in one document, which the check every message here goes through
// refuses as the shape of a wrapping attack. The message's own signature is checked
// where a signed request is required, on the way it would be checked arriving by
// POST.
func ReadArtifactResponse(body []byte) (*ArtifactResponse, error) {
	if err := scanForUnsafeConstructs(body); err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(body); err != nil {
		return nil, fmt.Errorf("the answer does not parse: %w", err)
	}
	env := doc.Root()
	if env == nil || env.Tag != "Envelope" || env.NamespaceURI() != nsSOAP11 {
		return nil, errors.New("the answer is not a SOAP 1.1 envelope")
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
	if len(children) != 1 || children[0].Tag != "ArtifactResponse" || children[0].NamespaceURI() != nsProtocol {
		return nil, errors.New("the body does not carry exactly one ArtifactResponse")
	}
	el := children[0]
	r := &ArtifactResponse{
		ID:           el.SelectAttrValue("ID", ""),
		InResponseTo: el.SelectAttrValue("InResponseTo", ""),
	}
	if r.ID == "" {
		return nil, errors.New("the ArtifactResponse has no ID")
	}
	if v := el.SelectAttrValue("Version", ""); v != "2.0" {
		return nil, fmt.Errorf("the ArtifactResponse is version %q, not 2.0", v)
	}
	var message *etree.Element
	for _, c := range el.ChildElements() {
		switch {
		case c.Tag == "Issuer" && c.NamespaceURI() == nsAssertion:
			// "the Format attribute MUST be omitted or have a value of
			// urn:oasis:names:tc:SAML:2.0:nameid-format:entity" (saml-profiles-2.0-os
			// lines 1495-1497).
			if f := c.SelectAttrValue("Format", ""); f != "" && f != nameIDFormatEntity {
				return nil, fmt.Errorf("the ArtifactResponse's Issuer has the format %q", f)
			}
			r.Issuer = strings.TrimSpace(c.Text())
		case c.Tag == "Status" && c.NamespaceURI() == nsProtocol:
			if code := c.SelectElement("StatusCode"); code != nil {
				r.StatusCode = code.SelectAttrValue("Value", "")
			}
		case c.Tag == "Signature" || c.Tag == "Extensions":
		default:
			if message != nil {
				return nil, errors.New("the ArtifactResponse carries more than one message")
			}
			message = c
		}
	}
	// "The <Issuer> element MUST be present" (line 1495).
	if r.Issuer == "" {
		return nil, errors.New("the ArtifactResponse names no Issuer")
	}
	if message != nil {
		lifted, err := standalone(message)
		if err != nil {
			return nil, err
		}
		r.Message = lifted
	}
	return r, nil
}

// MessageKind names the protocol message a document is, by its root element:
// "AuthnRequest", "LogoutRequest", "LogoutResponse". Unmarshal into a message's type
// does not check that, and a document fetched by artifact can be any of them.
func MessageKind(doc []byte) (string, error) {
	if err := scanForUnsafeConstructs(doc); err != nil {
		return "", err
	}
	d := etree.NewDocument()
	if err := d.ReadFromBytes(doc); err != nil {
		return "", fmt.Errorf("the message does not parse: %w", err)
	}
	root := d.Root()
	if root == nil || root.NamespaceURI() != nsProtocol {
		return "", errors.New("the message is not a SAML protocol message")
	}
	return root.Tag, nil
}

// standalone writes el as a document of its own, carrying the declarations of the
// namespace prefixes its names use that were declared on an ancestor. Those are the
// ones exclusive canonicalisation renders, so a signature made over the message
// before it was wrapped still verifies once it is unwrapped.
func standalone(el *etree.Element) ([]byte, error) {
	used := map[string]bool{}
	var walk func(*etree.Element)
	walk = func(e *etree.Element) {
		used[e.Space] = true
		for _, a := range e.Attr {
			if a.Space != "" && a.Space != "xmlns" {
				used[a.Space] = true
			}
		}
		for _, c := range e.ChildElements() {
			walk(c)
		}
	}
	walk(el)
	copied := el.Copy()
	declared := func(e *etree.Element, prefix string) bool {
		for _, a := range e.Attr {
			if (prefix == "" && a.Space == "" && a.Key == "xmlns") || (a.Space == "xmlns" && a.Key == prefix) {
				return true
			}
		}
		return false
	}
	for prefix := range used {
		if declared(el, prefix) {
			continue
		}
		for p := el.Parent(); p != nil; p = p.Parent() {
			if !declared(p, prefix) {
				continue
			}
			for _, a := range p.Attr {
				if prefix == "" && a.Space == "" && a.Key == "xmlns" {
					copied.CreateAttr("xmlns", a.Value)
				} else if a.Space == "xmlns" && a.Key == prefix {
					copied.CreateAttr("xmlns:"+prefix, a.Value)
				}
			}
			break
		}
	}
	out := etree.NewDocument()
	out.SetRoot(copied)
	return out.WriteToBytes()
}

// SOAPFault is the answer to a request that is not an ArtifactResolve this
// service can read, as a SOAP 1.1 Client fault.
func SOAPFault(reason string) string {
	var b bytes.Buffer
	b.WriteString(`<soap11:Envelope xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/"><soap11:Body>` +
		`<soap11:Fault><faultcode>soap11:Client</faultcode><faultstring>`)
	if err := xml.EscapeText(&b, []byte(reason)); err != nil {
		b.WriteString("the request was refused")
	}
	b.WriteString(`</faultstring></soap11:Fault></soap11:Body></soap11:Envelope>`)
	return b.String()
}
