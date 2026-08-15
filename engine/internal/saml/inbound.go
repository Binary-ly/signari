package saml

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
)


// refuseMultipleAssertions is always true outside the layering test.
var refuseMultipleAssertions = true

// InboundProvider is an upstream SAML identity provider.
type InboundProvider struct {
	// EntityID is the upstream's issuer, matched exactly against <Issuer>.
	EntityID string
	// SSOURL is where AuthnRequests are sent.
	SSOURL string
	// CertPEM is the signing certificate we expect. Supplied out of band or read
	// from the upstream's metadata; never taken from the response itself, which
	// would let a document vouch for its own signature.
	CertPEM string

	// SPEntityID is what we call ourselves to this provider.
	SPEntityID string
	// ACSURL is our assertion consumer service.
	ACSURL string

	// NameIDFormat requested. Empty asks for no particular format.
	NameIDFormat string
	// ForceAuthn asks the upstream to re-authenticate rather than reuse its
	// session. Used when stepping up.
	ForceAuthn bool

	// AllowUnsolicited permits IdP-initiated sign-in: a response with no
	// InResponseTo, arriving without us having asked.
	//
	// Off by default, and it should stay off. An unsolicited response cannot be
	// tied to a request this browser made, so a valid assertion captured from
	// anywhere -- a log, a proxy, another user's session -- can be posted into a
	// victim's browser to sign them in as somebody else. Some deployments need
	// it because their portal only does IdP-initiated flows, so it exists, with
	// its name saying what it is.
	AllowUnsolicited bool

	// SkewSeconds tolerates clock drift between us and the upstream. Bounded:
	// see clampSkew.
	SkewSeconds int
}

// AuthnRequestOut is a request to send to an upstream provider.
type AuthnRequestOut struct {
	// ID is remembered so the response's InResponseTo can be matched to it.
	ID string
	// RedirectURL is the full HTTP-Redirect binding URL, with RelayState.
	RedirectURL string
	// XML is the request document, for logging and tests.
	XML string
}

// BuildAuthnRequest builds a request to send to the upstream IdP.
//
// Unsigned. Most upstreams do not require SP-signed requests, and signing one
// requires a key exchange in the other direction that many deployments never
// complete. The security of this flow rests on verifying the RESPONSE, which is
// where the authentication claim actually lives.
func BuildAuthnRequest(p *InboundProvider, relayState string,
	now time.Time) (*AuthnRequestOut, error) {

	switch {
	case p.SSOURL == "":
		return nil, fmt.Errorf("provider has no SSO URL")
	case p.SPEntityID == "":
		return nil, fmt.Errorf("provider has no SP entity ID")
	case p.ACSURL == "":
		return nil, fmt.Errorf("provider has no assertion consumer service URL")
	}

	id, err := newID()
	if err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	req := doc.CreateElement("samlp:AuthnRequest")
	req.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	req.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	req.CreateAttr("ID", id)
	req.CreateAttr("Version", "2.0")
	req.CreateAttr("IssueInstant", now.UTC().Format(time.RFC3339))
	req.CreateAttr("Destination", p.SSOURL)
	req.CreateAttr("AssertionConsumerServiceURL", p.ACSURL)
	req.CreateAttr("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
	if p.ForceAuthn {
		req.CreateAttr("ForceAuthn", "true")
	}

	iss := req.CreateElement("saml:Issuer")
	iss.SetText(p.SPEntityID)

	if p.NameIDFormat != "" {
		np := req.CreateElement("samlp:NameIDPolicy")
		np.CreateAttr("Format", FullNameIDFormat(p.NameIDFormat))
		np.CreateAttr("AllowCreate", "true")
	}

	xml, err := doc.WriteToString()
	if err != nil {
		return nil, err
	}

	encoded, err := EncodeRedirect(xml)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(p.SSOURL)
	if err != nil {
		return nil, fmt.Errorf("SSO URL %q: %w", p.SSOURL, err)
	}
	q := u.Query()
	q.Set("SAMLRequest", encoded)
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	u.RawQuery = q.Encode()

	return &AuthnRequestOut{ID: id, RedirectURL: u.String(), XML: xml}, nil
}

// InboundAssertion is what an upstream provider told us about a person.
type InboundAssertion struct {
	// AssertionID is recorded so the same assertion cannot be used twice.
	AssertionID string
	// Subject is the NameID: the stable identifier this person is matched on.
	Subject string
	// SubjectFormat is the NameID Format, kept because a transient format is a
	// warning, not an identifier -- see CheckSubjectFormat.
	SubjectFormat string
	Email         string
	Name          string
	// Attributes is everything else, for group mapping.
	Attributes map[string][]string
	// SessionIndex ties a later logout request to this session.
	SessionIndex string
	// NotOnOrAfter is when the assertion stops being valid, used to bound how
	// long the replay record must be kept.
	NotOnOrAfter time.Time
}

// ConsumeOptions is the state a response is checked against.
type ConsumeOptions struct {
	// ExpectedInResponseTo is the ID of the AuthnRequest we sent. Empty means
	// this is an unsolicited response, allowed only if the provider says so.
	ExpectedInResponseTo string
	// Destination is our ACS URL, matched against the response.
	Destination string
	Now         time.Time
}

// ConsumeResponse verifies a SAML Response and extracts the assertion.
//
// The order matters: the signature is checked BEFORE anything inside the
// document is believed, and the wrapping defences run with it. Reading a field
// first and verifying afterwards is how signature-wrapping attacks work, because
// the parser and the verifier end up looking at different elements.
func ConsumeResponse(raw []byte, p *InboundProvider,
	opt ConsumeOptions) (*InboundAssertion, error) {

	if p.CertPEM == "" {
		return nil, fmt.Errorf("no signing certificate configured for %q: without one "+
			"there is nothing to verify the response against, and an unverified "+
			"assertion is an attacker's choice of user", p.EntityID)
	}

	// Entity expansion, DTDs and the rest, refused before a parser sees them.
	if err := scanForUnsafeConstructs(raw); err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, fmt.Errorf("parsing the response: %w", err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "Response" {
		return nil, fmt.Errorf("not a SAML Response")
	}

	// Status first: a failure carries no assertion, and reporting "no assertion
	// found" for a deliberate refusal sends operators looking in the wrong place.
	if err := checkStatus(root); err != nil {
		return nil, err
	}

	// More than one assertion anywhere in the document is refused before
	// anything is read. A second assertion is the payload of every wrapping
	// attack: one is signed, the other is the one the application reads, and
	// deciding which is which is the attacker's choice to offer.
	//
	// This guard is the OUTERMOST of several, and it is a var so the test can
	// switch it off and measure what the ones behind it actually achieve. Running
	// that experiment corrected the claim originally written here: without this
	// guard, the wrapping payloads never yield the forged subject -- claims come
	// from the element goxmldsig verified -- but one variant is ACCEPTED while
	// returning the honest subject. Harmless in itself, and a malformed document
	// accepted is where the next bug starts. So the guard earns its place by
	// refusing, not by preventing takeover.
	if all := doc.FindElements("//Assertion"); refuseMultipleAssertions && len(all) > 1 {
		return nil, fmt.Errorf("the response contains %d assertions; exactly one is "+
			"accepted, because choosing between them is the attacker's decision to make",
			len(all))
	}

	assertion := root.FindElement("./Assertion")
	if assertion == nil {
		if root.FindElement("./EncryptedAssertion") != nil {
			return nil, fmt.Errorf("the assertion is encrypted, which this provider is " +
				"not configured to decrypt")
		}
		return nil, fmt.Errorf("no assertion in the response")
	}
	assertionID := assertion.SelectAttrValue("ID", "")
	if assertionID == "" {
		return nil, fmt.Errorf("the assertion has no ID, so it cannot be replay-checked")
	}

	// The signature may cover the Response or the Assertion. Both are legal, and
	// an attacker gets to choose, so whichever is present must actually protect
	// the assertion we go on to read.
	//
	// verifyInbound returns THE ASSERTION INSIDE THE VERIFIED ELEMENT, and
	// everything below reads from that. Re-finding the assertion in the original
	// tree would reintroduce exactly the gap between "what was verified" and
	// "what was read" that this whole file is about.
	assertion, err := verifyInbound(doc, p.CertPEM, root, assertion, assertionID)
	if err != nil {
		return nil, err
	}

	// Only now is anything in the document worth reading.
	if err := checkIssuer(root, assertion, p.EntityID); err != nil {
		return nil, err
	}
	if err := checkInResponseTo(root, assertion, p, opt.ExpectedInResponseTo); err != nil {
		return nil, err
	}
	if err := checkDestination(root, opt.Destination); err != nil {
		return nil, err
	}

	skew := clampSkew(p.SkewSeconds)
	notOnOrAfter, err := checkConditions(assertion, p.SPEntityID, opt.Now, skew)
	if err != nil {
		return nil, err
	}

	out := &InboundAssertion{
		AssertionID:  assertionID,
		Attributes:   map[string][]string{},
		NotOnOrAfter: notOnOrAfter,
	}

	if nameID := assertion.FindElement("./Subject/NameID"); nameID != nil {
		out.Subject = strings.TrimSpace(nameID.Text())
		out.SubjectFormat = nameID.SelectAttrValue("Format", "")
	}
	if out.Subject == "" {
		return nil, fmt.Errorf("the assertion has no NameID, so there is no stable " +
			"identifier to match this person on")
	}

	if sc := assertion.FindElement("./AuthnStatement"); sc != nil {
		out.SessionIndex = sc.SelectAttrValue("SessionIndex", "")
	}

	for _, attr := range assertion.FindElements("./AttributeStatement/Attribute") {
		name := attr.SelectAttrValue("Name", "")
		if name == "" {
			continue
		}
		var vals []string
		for _, v := range attr.FindElements("./AttributeValue") {
			vals = append(vals, strings.TrimSpace(v.Text()))
		}
		if len(vals) == 0 {
			continue
		}
		out.Attributes[name] = vals
		switch {
		case isEmailAttr(name):
			if out.Email == "" {
				out.Email = vals[0]
			}
		case isNameAttr(name):
			if out.Name == "" {
				out.Name = vals[0]
			}
		}
	}

	// A NameID that IS an email is common, and is the only case where the
	// address comes from the identifier rather than an attribute.
	if out.Email == "" && strings.Contains(out.Subject, "@") &&
		!strings.EqualFold(out.SubjectFormat, FullNameIDFormat("transient")) {
		out.Email = out.Subject
	}

	return out, nil
}

// verifyInbound checks the signature wherever it legitimately sits.
//
// A Response may be signed at the Response level, at the Assertion level, or
// both. The danger is that an attacker adds a second, valid-looking signature
// over an element that is not the one read afterwards -- which is exactly what
// VerifyEmbeddedSignature's placement check exists to prevent.
func verifyInbound(doc *etree.Document, certPEM string, root, assertion *etree.Element,
	assertionID string) (*etree.Element, error) {

	responseSigned := root.FindElement("./Signature") != nil
	assertionSigned := assertion.FindElement("./Signature") != nil

	switch {
	case assertionSigned:
		// Preferred: the signature covers exactly the element read afterwards.
		return verifySignedElement(doc, assertion, certPEM, "Assertion", assertionID)

	case responseSigned:
		// Legal, and weaker: the assertion is covered only because it sits inside
		// the response. That is sound as long as the assertion read afterwards is
		// the one INSIDE the verified response, which is why the child is taken
		// from the verified element rather than from the original tree.
		responseID := root.SelectAttrValue("ID", "")
		if responseID == "" {
			return nil, fmt.Errorf("the response is signed but has no ID")
		}
		verified, err := verifySignedElement(doc, root, certPEM, "Response", responseID)
		if err != nil {
			return nil, err
		}
		inner := verified.FindElement("./Assertion")
		if inner == nil {
			return nil, fmt.Errorf("the signed response contains no assertion")
		}
		if got := inner.SelectAttrValue("ID", ""); got != assertionID {
			return nil, fmt.Errorf("the signed response carries assertion %q, not the "+
				"assertion being processed (%q)", got, assertionID)
		}
		return inner, nil

	default:
		return nil, fmt.Errorf("neither the response nor the assertion is signed: an " +
			"unsigned assertion is a claim by whoever sent it, which for a browser " +
			"POST is anybody at all")
	}
}

func checkStatus(root *etree.Element) error {
	sc := root.FindElement("./Status/StatusCode")
	if sc == nil {
		return fmt.Errorf("the response has no status")
	}
	code := sc.SelectAttrValue("Value", "")
	if code == "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return nil
	}
	msg := ""
	if m := root.FindElement("./Status/StatusMessage"); m != nil {
		msg = ": " + strings.TrimSpace(m.Text())
	}
	// Second-level codes carry the actual reason often enough to be worth it.
	if inner := root.FindElement("./Status/StatusCode/StatusCode"); inner != nil {
		msg += " (" + inner.SelectAttrValue("Value", "") + ")"
	}
	return fmt.Errorf("the provider refused the sign-in%s [%s]", msg, shortStatus(code))
}

func checkIssuer(root, assertion *etree.Element, want string) error {
	if want == "" {
		return fmt.Errorf("no expected entity ID configured for this provider")
	}
	// The assertion's issuer is the one that matters: it is the element making
	// the authentication claim. A response-level issuer that disagrees is a
	// mixed document and is refused rather than reconciled.
	got := ""
	if iss := assertion.FindElement("./Issuer"); iss != nil {
		got = strings.TrimSpace(iss.Text())
	}
	if got == "" {
		if iss := root.FindElement("./Issuer"); iss != nil {
			got = strings.TrimSpace(iss.Text())
		}
	}
	if got != want {
		return fmt.Errorf("the assertion was issued by %q, not by the configured "+
			"provider %q", got, want)
	}
	if riss := root.FindElement("./Issuer"); riss != nil {
		if r := strings.TrimSpace(riss.Text()); r != "" && r != want {
			return fmt.Errorf("the response says it is from %q while the assertion "+
				"inside says %q", r, want)
		}
	}
	return nil
}

// checkInResponseTo ties the assertion to a request this browser made.
//
// The single most important check after the signature. Without it a valid
// assertion -- from a log, a proxy, a shared machine, another user's browser --
// can be posted into a victim's session and signs them in as somebody else. The
// signature says the upstream minted it; only this says it was minted for now,
// for this browser, because we asked.
func checkInResponseTo(root, assertion *etree.Element, p *InboundProvider,
	expected string) error {

	got := root.SelectAttrValue("InResponseTo", "")

	// The subject confirmation carries it too, and both must agree: a document
	// where they differ is trying to satisfy two readers at once.
	scGot := ""
	if scd := assertion.FindElement("./Subject/SubjectConfirmation/SubjectConfirmationData"); scd != nil {
		scGot = scd.SelectAttrValue("InResponseTo", "")
	}
	if got != "" && scGot != "" && got != scGot {
		return fmt.Errorf("the response answers request %q while the assertion inside "+
			"answers %q", got, scGot)
	}
	if got == "" {
		got = scGot
	}

	if expected == "" {
		if got != "" {
			return fmt.Errorf("this response answers request %q, but no such request "+
				"is outstanding for this browser -- it may have already been used, or "+
				"it may belong to a different session", got)
		}
		if !p.AllowUnsolicited {
			return fmt.Errorf("unsolicited assertion refused: it cannot be tied to a " +
				"request this browser made, so a valid assertion captured anywhere " +
				"could be posted here to sign somebody in. Enable unsolicited " +
				"sign-in on this provider only if its portal requires it")
		}
		return nil
	}

	if got != expected {
		return fmt.Errorf("this response answers request %q, not the one this browser "+
			"sent", got)
	}
	return nil
}

func checkDestination(root *etree.Element, want string) error {
	got := root.SelectAttrValue("Destination", "")
	if got == "" {
		// Optional in the schema, and its absence is not by itself an attack.
		return nil
	}
	if want == "" || !sameURL(got, want) {
		return fmt.Errorf("the response was addressed to %q, not to this endpoint "+
			"(%q); an assertion minted for another service is not ours to accept",
			got, want)
	}
	return nil
}

// checkConditions validates the time window and the audience.
func checkConditions(assertion *etree.Element, spEntityID string, now time.Time,
	skew time.Duration) (time.Time, error) {

	cond := assertion.FindElement("./Conditions")
	if cond == nil {
		return time.Time{}, fmt.Errorf("the assertion has no Conditions, so it has no " +
			"expiry and no audience -- it would be valid forever, for anyone")
	}

	var notOnOrAfter time.Time
	if v := cond.SelectAttrValue("NotBefore", ""); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, fmt.Errorf("NotBefore %q is not a timestamp: %w", v, err)
		}
		if now.Add(skew).Before(t) {
			return time.Time{}, fmt.Errorf("the assertion is not valid until %s "+
				"(now %s, tolerating %s of clock drift)", t.Format(time.RFC3339),
				now.UTC().Format(time.RFC3339), skew)
		}
	}
	if v := cond.SelectAttrValue("NotOnOrAfter", ""); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, fmt.Errorf("NotOnOrAfter %q is not a timestamp: %w", v, err)
		}
		if !now.Add(-skew).Before(t) {
			return time.Time{}, fmt.Errorf("the assertion expired at %s (now %s)",
				t.Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		}
		notOnOrAfter = t
	}

	// The audience is what stops an assertion minted for a different service
	// being replayed here. An assertion with no AudienceRestriction at all is
	// addressed to everybody, which includes attackers.
	restrictions := cond.FindElements("./AudienceRestriction")
	if len(restrictions) == 0 {
		return time.Time{}, fmt.Errorf("the assertion has no AudienceRestriction: it " +
			"is addressed to everybody, so an assertion minted for any other service " +
			"would be accepted here")
	}
	found := false
	var seen []string
	for _, r := range restrictions {
		for _, a := range r.FindElements("./Audience") {
			v := strings.TrimSpace(a.Text())
			seen = append(seen, v)
			if v == spEntityID {
				found = true
			}
		}
	}
	if !found {
		return time.Time{}, fmt.Errorf("the assertion is addressed to %v, not to us "+
			"(%q)", seen, spEntityID)
	}

	// The subject confirmation has its own expiry, and it is usually shorter.
	if scd := assertion.FindElement(
		"./Subject/SubjectConfirmation/SubjectConfirmationData"); scd != nil {
		if v := scd.SelectAttrValue("NotOnOrAfter", ""); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return time.Time{}, fmt.Errorf("SubjectConfirmationData NotOnOrAfter "+
					"%q is not a timestamp: %w", v, err)
			}
			if !now.Add(-skew).Before(t) {
				return time.Time{}, fmt.Errorf("the subject confirmation expired at %s",
					t.Format(time.RFC3339))
			}
			if notOnOrAfter.IsZero() || t.Before(notOnOrAfter) {
				notOnOrAfter = t
			}
		}
	}

	if notOnOrAfter.IsZero() {
		return time.Time{}, fmt.Errorf("the assertion never expires, so a copy of it " +
			"would be a permanent credential")
	}
	return notOnOrAfter, nil
}

// clampSkew bounds the clock tolerance.
//
// Skew is the setting operators reach for when a clock is wrong, and a large
// value quietly extends how long a captured assertion stays replayable. Five
// minutes is the conventional ceiling and is enough for any correctly
// synchronised pair of machines.
func clampSkew(seconds int) time.Duration {
	const maxSkew = 5 * time.Minute
	if seconds <= 0 {
		return 30 * time.Second
	}
	d := time.Duration(seconds) * time.Second
	if d > maxSkew {
		return maxSkew
	}
	return d
}

// CheckSubjectFormat reports a transient NameID, which is not an identifier.
//
// A transient NameID is deliberately different on every sign-in. Storing one as
// the account's subject creates a new account every time the person signs in,
// each orphaned immediately. Callers refuse it rather than build that.
func CheckSubjectFormat(format string) error {
	if strings.EqualFold(format, FullNameIDFormat("transient")) {
		return fmt.Errorf("this provider sends a transient NameID, which is a " +
			"different value on every sign-in. Linking accounts to it would create a " +
			"new account each time somebody signs in. Configure the provider to send " +
			"a persistent NameID or an email address")
	}
	return nil
}

func isEmailAttr(name string) bool {
	switch strings.ToLower(name) {
	case "email", "mail", "emailaddress",
		"urn:oid:0.9.2342.19200300.100.1.3",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		"urn:oasis:names:tc:saml:attribute:subject-id":
		return true
	}
	return strings.HasSuffix(strings.ToLower(name), "emailaddress")
}

func isNameAttr(name string) bool {
	switch strings.ToLower(name) {
	case "name", "displayname", "cn", "urn:oid:2.5.4.3",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
		"http://schemas.microsoft.com/identity/claims/displayname":
		return true
	}
	return false
}

func shortStatus(urn string) string {
	if i := strings.LastIndex(urn, ":"); i >= 0 && i+1 < len(urn) {
		return urn[i+1:]
	}
	return urn
}

// RelayStateToken makes an opaque RelayState value.
//
// RelayState is echoed back by the upstream and is therefore attacker-visible
// and attacker-modifiable. It carries a lookup key here, never a destination:
// putting a URL in it is how SAML deployments grow open redirects.
func RelayStateToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
