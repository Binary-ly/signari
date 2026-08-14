package saml

import (
	"compress/flate"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// Single logout.
//
// # The advisory that shapes this file
//
// gosaml2 GHSA-pcgw-qcv5-h8ch: unsigned LogoutRequests were accepted. Anyone who
// could reach the endpoint could sign any user out of anything, with no
// credential at all. It is the cheapest possible denial of service against an
// identity provider, and it needs no access.
//
// So: a LogoutRequest is acted on ONLY if it carries a signature that verifies
// against a certificate registered for that service provider in advance. No
// certificate on file means logout from that provider is refused rather than
// trusted -- an inconvenience, chosen deliberately over the alternative.

// LogoutRequest is an SP asking us to end a session.
type LogoutRequest struct {
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	Destination  string `xml:"Destination,attr"`
	Issuer       string `xml:"Issuer"`
	NameID       string `xml:"NameID"`
	SessionIndex string `xml:"SessionIndex"`
}

// ValidatedLogout is a request that passed every check.
type ValidatedLogout struct {
	RequestID    string
	Issuer       string
	NameID       string
	SessionIndex string
}

// ValidateLogoutRequest checks everything except the signature, which is
// binding-specific and handled by VerifyRedirectSignature.
func ValidateLogoutRequest(r *LogoutRequest, p *Provider, destination string, now time.Time) (*ValidatedLogout, error) {
	if !p.Enabled {
		return nil, fmt.Errorf("service provider %q is disabled", p.EntityID)
	}
	if r.ID == "" {
		return nil, fmt.Errorf("LogoutRequest has no ID")
	}
	if r.Version != "2.0" {
		return nil, fmt.Errorf("LogoutRequest Version is %q, expected 2.0", r.Version)
	}
	if r.Issuer != p.EntityID {
		return nil, fmt.Errorf("LogoutRequest Issuer %q does not match the provider %q",
			r.Issuer, p.EntityID)
	}
	if r.NameID == "" {
		return nil, fmt.Errorf("LogoutRequest names no subject, so there is nothing to end")
	}
	if r.Destination != "" && !sameURL(r.Destination, destination) {
		return nil, fmt.Errorf("LogoutRequest Destination is %q, but this endpoint is %q",
			r.Destination, destination)
	}
	if r.IssueInstant != "" {
		t, err := time.Parse(time.RFC3339, r.IssueInstant)
		if err != nil {
			return nil, fmt.Errorf("LogoutRequest IssueInstant %q is not a valid timestamp: %w",
				r.IssueInstant, err)
		}
		if d := now.Sub(t); d > clockSkew || d < -clockSkew {
			return nil, fmt.Errorf("LogoutRequest IssueInstant is %s away from now, "+
				"outside the %s tolerance", d.Round(time.Second), clockSkew)
		}
	}
	return &ValidatedLogout{
		RequestID: r.ID, Issuer: r.Issuer,
		NameID: r.NameID, SessionIndex: r.SessionIndex,
	}, nil
}

// Signature algorithms we accept on the redirect binding.
const (
	sigAlgRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	sigAlgRSASHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
)

// VerifyRedirectSignature checks the signature on an HTTP-Redirect binding
// message.
//
// # Why this cannot use the XML signature code
//
// On the redirect binding the signature is NOT part of the document. It is
// computed over the raw query-string octets and carried in separate `SigAlg`
// and `Signature` parameters (SAML Bindings 3.4.4.1). A document arriving this
// way may also contain a <ds:Signature> element, and verifying THAT instead
// proves nothing about the request as it was actually sent -- the attacker
// supplied the whole document.
//
// # Why the raw query string matters
//
// The signed bytes are the parameters in a fixed order, percent-encoded exactly
// as the sender encoded them:
//
//	SAMLRequest=...&RelayState=...&SigAlg=...
//
// Re-encoding from a parsed map is the classic mistake here. Go's url.Encode
// escapes a different set of characters than the sender's library, sorts keys
// alphabetically, and drops an empty RelayState -- so the bytes verified are
// not the bytes signed, and every legitimate request fails while a
// specially-crafted one may not. The raw substrings are used instead.
func VerifyRedirectSignature(rawQuery string, certPEM string, param string) error {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return fmt.Errorf("the query string did not parse: %w", err)
	}
	sigB64 := values.Get("Signature")
	sigAlg := values.Get("SigAlg")
	if sigB64 == "" || sigAlg == "" {
		return fmt.Errorf("the request is not signed. A LogoutRequest is acted on only " +
			"when signed, because an unsigned one lets anybody sign anybody out")
	}

	switch sigAlg {
	case sigAlgRSASHA256:
	case sigAlgRSASHA1:
		// SHA-1 is refused rather than accepted-with-a-warning. Chosen-prefix
		// collisions against SHA-1 are practical, and a warning nobody reads is
		// not a control.
		return fmt.Errorf("the request is signed with RSA-SHA1, which is refused; " +
			"configure the service provider to use rsa-sha256")
	default:
		return fmt.Errorf("unsupported signature algorithm %q", sigAlg)
	}

	signed, err := signedOctets(rawQuery, param)
	if err != nil {
		return err
	}

	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("the registered certificate for this service provider is not RSA")
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("the signature is not valid base64: %w", err)
	}
	sum := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return fmt.Errorf("the signature did not verify against the certificate registered "+
			"for this service provider: %w", err)
	}
	return nil
}

// signedOctets rebuilds the exact string the sender signed.
//
// Taken as raw substrings of the query in the order the specification fixes,
// never re-encoded. param is "SAMLRequest" or "SAMLResponse".
func signedOctets(rawQuery, param string) (string, error) {
	get := func(name string) (string, bool) {
		for _, pair := range strings.Split(rawQuery, "&") {
			if k, v, ok := strings.Cut(pair, "="); ok && k == name {
				return v, true
			}
		}
		return "", false
	}

	msg, ok := get(param)
	if !ok {
		return "", fmt.Errorf("the query carries no %s", param)
	}
	parts := []string{param + "=" + msg}
	// RelayState is included ONLY when present, and in this position. Including
	// an empty one, or moving it, changes the bytes.
	if rs, ok := get("RelayState"); ok {
		parts = append(parts, "RelayState="+rs)
	}
	alg, ok := get("SigAlg")
	if !ok {
		return "", fmt.Errorf("the query carries no SigAlg")
	}
	parts = append(parts, "SigAlg="+alg)
	return strings.Join(parts, "&"), nil
}

func parseCertPEM(certPEM string) (*x509.Certificate, error) {
	if strings.TrimSpace(certPEM) == "" {
		return nil, fmt.Errorf("no signing certificate is registered for this service " +
			"provider, so its logout requests cannot be verified and are refused. " +
			"Register one before enabling single logout")
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("the registered certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the registered certificate did not parse: %w", err)
	}
	return cert, nil
}

// LogoutResponseInput builds our answer to a LogoutRequest.
type LogoutResponseInput struct {
	Issuer      string
	Destination string
	InResponse  string
	Status      string
	Now         time.Time
}

// BuildLogoutResponse renders a LogoutResponse.
//
// Signed, unlike the error responses in assertion.go. A logout response is
// acted on by the service provider -- it ends a session on the strength of it --
// so it is a statement with a consequence, and the receiver is entitled to
// verify that we made it.
func BuildLogoutResponse(in LogoutResponseInput, signer crypto.Signer, certDER []byte) (string, error) {
	if in.Destination == "" {
		return "", fmt.Errorf("refusing to build a LogoutResponse with no Destination")
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	now := in.Now.UTC().Truncate(time.Second)
	status := in.Status
	if status == "" {
		status = StatusSuccess
	}

	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:LogoutResponse")
	resp.CreateAttr("xmlns:samlp", nsProtocol)
	resp.CreateAttr("xmlns:saml", nsAssertion)
	resp.CreateAttr("ID", id)
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	resp.CreateAttr("Destination", in.Destination)
	if in.InResponse != "" {
		resp.CreateAttr("InResponseTo", in.InResponse)
	}
	resp.CreateElement("saml:Issuer").SetText(in.Issuer)
	st := resp.CreateElement("samlp:Status")
	st.CreateElement("samlp:StatusCode").CreateAttr("Value", status)

	signed, err := signElement(resp, signer, certDER)
	if err != nil {
		return "", fmt.Errorf("signing the LogoutResponse: %w", err)
	}
	// Same schema-ordering rule as an assertion: StatusResponseType fixes
	// Issuer, Signature, Extensions, Status. goxmldsig appends, so the signature
	// lands after Status and the document is invalid to anything that validates.
	if err := moveSignatureAfterIssuer(signed); err != nil {
		return "", err
	}

	out := etree.NewDocument()
	out.SetRoot(signed)
	return out.WriteToString()
}

// LogoutRequestInput builds a LogoutRequest we send to a service provider when
// the user signs out of Signari.
type LogoutRequestInput struct {
	Issuer       string
	Destination  string
	NameID       string
	NameIDFormat string
	SessionIndex string
	Now          time.Time
}

// BuildLogoutRequest renders an IdP-initiated LogoutRequest.
//
// The NameID and SessionIndex must be EXACTLY what we sent in the original
// assertion. A service provider matches on them, so a request carrying anything
// else is accepted and quietly ends nothing -- which is indistinguishable from
// working, right up until someone checks.
func BuildLogoutRequest(in LogoutRequestInput, signer crypto.Signer, certDER []byte) (string, error) {
	if in.Destination == "" {
		return "", fmt.Errorf("refusing to build a LogoutRequest with no Destination")
	}
	if in.NameID == "" {
		return "", fmt.Errorf("refusing to build a LogoutRequest with no NameID: the " +
			"service provider would have nothing to match and would end nothing")
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	now := in.Now.UTC().Truncate(time.Second)

	doc := etree.NewDocument()
	req := doc.CreateElement("samlp:LogoutRequest")
	req.CreateAttr("xmlns:samlp", nsProtocol)
	req.CreateAttr("xmlns:saml", nsAssertion)
	req.CreateAttr("ID", id)
	req.CreateAttr("Version", "2.0")
	req.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	req.CreateAttr("Destination", in.Destination)
	req.CreateElement("saml:Issuer").SetText(in.Issuer)

	nameID := req.CreateElement("saml:NameID")
	if in.NameIDFormat != "" {
		nameID.CreateAttr("Format", in.NameIDFormat)
	}
	nameID.SetText(in.NameID)

	if in.SessionIndex != "" {
		req.CreateElement("samlp:SessionIndex").SetText(in.SessionIndex)
	}

	signed, err := signElement(req, signer, certDER)
	if err != nil {
		return "", fmt.Errorf("signing the LogoutRequest: %w", err)
	}
	if err := moveSignatureAfterIssuer(signed); err != nil {
		return "", err
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	return out.WriteToString()
}

// newFlateWriter produces the RAW deflate stream the binding specifies -- no
// zlib header, which is what compress/flate gives and compress/zlib does not.
func newFlateWriter(w io.Writer) (*flate.Writer, error) {
	return flate.NewWriter(w, flate.BestCompression)
}

// EncodeRedirect prepares a document for the HTTP-Redirect binding: raw DEFLATE,
// then base64.
func EncodeRedirect(doc string) (string, error) {
	var buf strings.Builder
	b64 := base64.NewEncoder(base64.StdEncoding, &buf)
	fw, err := newFlateWriter(b64)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write([]byte(doc)); err != nil {
		return "", err
	}
	if err := fw.Close(); err != nil {
		return "", err
	}
	if err := b64.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// SignRedirectQuery builds a signed HTTP-Redirect binding query string.
//
// The bytes we sign and the bytes we send MUST be the same, and the only way to
// guarantee that is to build one string and derive the other from it. Encoding
// twice -- once to sign, once to send -- is how an implementation signs `%7E`
// and transmits `~`, producing a signature that fails at every receiver while
// looking correct in every log.
//
// This is the mirror of VerifyRedirectSignature, and the two are tested against
// each other precisely because a shared misunderstanding of the encoding would
// otherwise stay invisible.
func SignRedirectQuery(param, encodedDoc, relayState string, signer crypto.Signer) (string, error) {
	key, ok := signer.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("SAML redirect signing needs an in-process RSA key, got %T", signer)
	}

	parts := []string{param + "=" + url.QueryEscape(encodedDoc)}
	if relayState != "" {
		parts = append(parts, "RelayState="+url.QueryEscape(relayState))
	}
	parts = append(parts, "SigAlg="+url.QueryEscape(sigAlgRSASHA256))
	signed := strings.Join(parts, "&")

	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("signing the redirect query: %w", err)
	}
	// Appended to the EXACT string that was signed, never rebuilt from a map.
	return signed + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig)), nil
}
