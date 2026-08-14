package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"

	StatusSuccess           = "urn:oasis:names:tc:SAML:2.0:status:Success"
	StatusRequester         = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	StatusResponder         = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	StatusNoPassive         = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
	StatusAuthnFailed       = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	StatusInvalidNameID     = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
	confirmationBearer      = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	AuthnContextPassword    = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	AuthnContextMFA         = "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication"
	AuthnContextUnspecified = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
)

// Subject is the person the assertion is about.
type Subject struct {
	NameID       string
	NameIDFormat string
	SessionIndex string
	AuthnInstant time.Time
	AuthnContext string
	Attributes   map[string][]string
}

// ResponseInput is everything needed to build a signed response.
type ResponseInput struct {
	Issuer      string // our entity id
	Destination string // the ACS URL, already validated
	InResponse  string // the AuthnRequest ID, empty for IdP-initiated
	Audience    string // the SP entity id
	Subject     Subject
	Lifetime    time.Duration
	Now         time.Time
}

// BuildResponse constructs a signed SAML Response.
//
// # What makes an assertion safe
//
// The signature is necessary and nowhere near sufficient. A correctly signed
// assertion that omits any of the following is still a serious vulnerability,
// and each is easy to leave out because nothing complains when you do:
//
//   - AudienceRestriction. Without it an assertion issued for one service
//     provider is valid at EVERY other one. Whoever runs a low-value SP can
//     replay its assertions into a high-value one.
//   - SubjectConfirmationData/@Recipient. Ties the assertion to the ACS URL it
//     was delivered to, so an assertion captured at one endpoint cannot be
//     posted to another.
//   - @InResponseTo. Ties it to the request that asked for it, which is what
//     stops an assertion being injected into a login the user never started.
//   - @NotOnOrAfter, in both Conditions and SubjectConfirmationData. An
//     assertion with no expiry is a bearer credential valid forever.
//
// A test asserting each of these is present is at the bottom of the file's test
// suite, because "we sign it" is the part everyone gets right.
func BuildResponse(in ResponseInput, kid string, signer crypto.Signer, certDER []byte) (string, error) {
	if in.Audience == "" {
		return "", fmt.Errorf("refusing to build an assertion with no Audience: it would " +
			"be valid at every service provider, not just the one that asked")
	}
	if in.Destination == "" {
		return "", fmt.Errorf("refusing to build an assertion with no Destination")
	}
	if in.Lifetime <= 0 {
		return "", fmt.Errorf("refusing to build an assertion with no lifetime: it would " +
			"never expire")
	}
	if _, err := SignatureMethod(signer); err != nil {
		return "", err
	}

	now := in.Now.UTC().Truncate(time.Second)
	notOnOrAfter := now.Add(in.Lifetime)
	// Backdated slightly for the same reason as the certificate: an SP whose
	// clock is a little behind ours must not reject a fresh assertion.
	notBefore := now.Add(-clockSkew)

	respID, err := newID()
	if err != nil {
		return "", err
	}
	assertionID, err := newID()
	if err != nil {
		return "", err
	}

	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsProtocol)
	resp.CreateAttr("xmlns:saml", nsAssertion)
	resp.CreateAttr("ID", respID)
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	resp.CreateAttr("Destination", in.Destination)
	if in.InResponse != "" {
		resp.CreateAttr("InResponseTo", in.InResponse)
	}

	issuer := resp.CreateElement("saml:Issuer")
	issuer.SetText(in.Issuer)

	status := resp.CreateElement("samlp:Status")
	status.CreateElement("samlp:StatusCode").CreateAttr("Value", StatusSuccess)

	assertion := buildAssertion(assertionID, in, now, notBefore, notOnOrAfter)

	// # Signing the ASSERTION, not the Response
	//
	// This is the signature-wrapping decision, and it is the one that the CVE
	// record is full of. If only the Response is signed, an attacker who obtains
	// one valid response can often move the signed element aside and insert their
	// own assertion -- the document still contains a valid signature over
	// something, and a verifier that checks "is there a valid signature" rather
	// than "is the element I am reading the one that was signed" accepts it.
	//
	// Signing the assertion itself means the thing carrying the identity is the
	// thing covered by the signature. Response signing is available as well, and
	// is additional rather than instead.
	signed, err := signElement(assertion, signer, certDER)
	if err != nil {
		return "", fmt.Errorf("signing the assertion: %w", err)
	}
	resp.AddChild(signed)

	// NOT indented. etree's Indent inserts whitespace text nodes between
	// elements, and doing that after signing changes the bytes the digest was
	// computed over -- the signature then fails to verify everywhere, while the
	// document looks perfect to a human reading it. Any pretty-printing must
	// happen before signing or not at all.
	out, err := doc.WriteToString()
	if err != nil {
		return "", err
	}
	return out, nil
}

func buildAssertion(id string, in ResponseInput, now, notBefore, notOnOrAfter time.Time) *etree.Element {
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", nsAssertion)
	a.CreateAttr("ID", id)
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", now.Format(time.RFC3339))

	// Element order is fixed by the schema, and a validating service provider
	// will reject an assertion whose children are out of sequence -- Issuer,
	// Signature, Subject, Conditions, AuthnStatement, AttributeStatement.
	a.CreateElement("saml:Issuer").SetText(in.Issuer)

	subject := a.CreateElement("saml:Subject")
	nameID := subject.CreateElement("saml:NameID")
	nameID.CreateAttr("Format", in.Subject.NameIDFormat)
	nameID.SetText(in.Subject.NameID)

	sc := subject.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", confirmationBearer)
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("NotOnOrAfter", notOnOrAfter.Format(time.RFC3339))
	// Recipient and InResponseTo are what bind this assertion to THIS delivery
	// and THIS request. Omitting them is how a captured assertion becomes
	// replayable somewhere else.
	scd.CreateAttr("Recipient", in.Destination)
	if in.InResponse != "" {
		scd.CreateAttr("InResponseTo", in.InResponse)
	}

	conditions := a.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", notBefore.Format(time.RFC3339))
	conditions.CreateAttr("NotOnOrAfter", notOnOrAfter.Format(time.RFC3339))
	ar := conditions.CreateElement("saml:AudienceRestriction")
	ar.CreateElement("saml:Audience").SetText(in.Audience)

	as := a.CreateElement("saml:AuthnStatement")
	as.CreateAttr("AuthnInstant", in.Subject.AuthnInstant.UTC().Format(time.RFC3339))
	if in.Subject.SessionIndex != "" {
		// Carried so that single logout can name this session later. Without it a
		// LogoutRequest cannot say WHICH session to end, and SPs that track more
		// than one per user will end none of them.
		as.CreateAttr("SessionIndex", in.Subject.SessionIndex)
	}
	ctx := as.CreateElement("saml:AuthnContext")
	class := in.Subject.AuthnContext
	if class == "" {
		class = AuthnContextUnspecified
	}
	ctx.CreateElement("saml:AuthnContextClassRef").SetText(class)

	if len(in.Subject.Attributes) > 0 {
		stmt := a.CreateElement("saml:AttributeStatement")
		for _, name := range sortedKeys(in.Subject.Attributes) {
			attr := stmt.CreateElement("saml:Attribute")
			attr.CreateAttr("Name", name)
			attr.CreateAttr("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
			for _, v := range in.Subject.Attributes[name] {
				av := attr.CreateElement("saml:AttributeValue")
				av.SetText(v)
			}
		}
	}
	return a
}

// signElement applies an enveloped signature over el.
func signElement(el *etree.Element, signer crypto.Signer, certDER []byte) (*etree.Element, error) {
	key, ok := signer.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("this signing key does not expose its private material "+
			"(it is %T, likely an external key store), and the XML signature library "+
			"requires an in-process RSA key. Use a software RS256 key for SAML", signer)
	}
	ctx := &dsig.SigningContext{
		Hash: crypto.SHA256,
		KeyStore: staticKeyStore{
			key:  key,
			cert: certDER,
		},
		IdAttribute: "ID",
		// The `ds:` prefix, rather than making xmldsig the default namespace.
		// Both are correct XML and mean exactly the same thing, but a good deal of
		// service-provider software matches element names as strings rather than
		// resolving namespaces, and `ds:Signature` is what every other identity
		// provider emits. Being technically right here buys nothing and costs
		// interoperability.
		Prefix: "ds",
		// Exclusive canonicalisation WITHOUT comments. This is the algorithm the
		// SAML profile specifies, and the "without comments" half is what the
		// comment-truncation attacks abuse -- the digest is computed over a
		// document with comments removed, so a comment can change what a parser
		// reads without changing what was signed. We refuse comments on the way
		// in (see decode.go) rather than relying on this.
		Canonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, err
	}
	return ctx.SignEnveloped(el)
}

// staticKeyStore hands goxmldsig the one key we are signing with.
//
// Its interface demands a *rsa.PrivateKey rather than a crypto.Signer, so a key
// held somewhere that will not export its private material -- an HSM, a KMS,
// anything reached through signing_keys.key_ref -- CANNOT be used for SAML
// through this path. That is a real limitation of the library and it is
// surfaced as a clear error at signing time rather than a type assertion panic.
type staticKeyStore struct {
	key  *rsa.PrivateKey
	cert []byte
}

func (s staticKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return s.key, s.cert, nil
}

// newID generates an assertion or response identifier.
//
// It MUST start with a letter or underscore: the type is xsd:ID, and a value
// beginning with a digit is invalid XML. Schema-validating service providers
// reject it, and -- worse -- non-validating ones accept it, so the deployment
// works everywhere except the one customer who validates.
//
// It must also be unpredictable, because InResponseTo matching is one of the
// things standing between a user and an injected assertion.
func newID() (string, error) {
	b := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generating an identifier: %w", err)
	}
	return "_" + hex.EncodeToString(b), nil
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Deterministic output. Not security-relevant, but a diffable assertion is
	// worth a great deal when debugging an SP that rejects one and accepts another.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// ParseCertificate is a convenience for callers holding stored DER.
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}
