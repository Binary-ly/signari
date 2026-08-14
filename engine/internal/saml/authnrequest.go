package saml

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// AuthnRequest is what a service provider sends to start a login.
//
// Only the fields we ACT on are modelled. An unmodelled field is one we cannot
// accidentally trust, and SAML's surface is large enough that "parse everything
// and decide later" is how implementations end up honouring something they
// never meant to support.
type AuthnRequest struct {
	ID                          string `xml:"ID,attr"`
	Version                     string `xml:"Version,attr"`
	IssueInstant                string `xml:"IssueInstant,attr"`
	Destination                 string `xml:"Destination,attr"`
	AssertionConsumerServiceURL string `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding             string `xml:"ProtocolBinding,attr"`
	ForceAuthn                  string `xml:"ForceAuthn,attr"`
	IsPassive                   string `xml:"IsPassive,attr"`

	Issuer string `xml:"Issuer"`

	NameIDPolicy struct {
		Format string `xml:"Format,attr"`
	} `xml:"NameIDPolicy"`

	RequestedAuthnContext struct {
		Comparison string   `xml:"Comparison,attr"`
		ClassRefs  []string `xml:"AuthnContextClassRef"`
	} `xml:"RequestedAuthnContext"`

	// Signature is modelled ONLY so its presence can be detected. It is never
	// used as evidence: on the HTTP-Redirect binding the signature is a query
	// parameter over the raw octets, not part of the document, and treating an
	// embedded <ds:Signature> element as proof is how "something in here was
	// signed" becomes "this request is authentic".
	Signature *struct{} `xml:"Signature"`
}

// Provider is a registered service provider, as the request is checked against.
type Provider struct {
	ID                      string
	OrgID                   string
	EntityID                string
	DisplayName             string
	ACSURLs                 []ACSURL
	NameIDFormat            string
	SignAssertions          bool
	SignResponses           bool
	WantAuthnRequestsSigned bool
	SPSigningCert           string
	// SPEncryptionCert is the SEPARATE certificate the assertion is encrypted
	// to. Empty means no encryption; TLS is the transport either way.
	SPEncryptionCert string
	LifetimeSeconds  int
	Enabled          bool
}

type ACSURL struct {
	URL       string
	Binding   string
	IsDefault bool
}

// Validated is an AuthnRequest that has passed every check, carrying the values
// the caller should use.
//
// The ACS URL is returned here rather than read back off the request, so that a
// caller cannot use the unvalidated one by accident. That mistake is the SAML
// equivalent of honouring an unregistered redirect_uri, and it delivers a valid
// assertion for a real user to a server the attacker controls.
type Validated struct {
	RequestID string
	Issuer    string
	// IssueInstant is when the service provider asked. Carried because it is
	// what makes ForceAuthn decidable: a session established AFTER this moment
	// is, by definition, a fresh authentication for this request.
	IssueInstant time.Time
	ACSURL       string
	Binding      string
	NameIDFormat string
	ForceAuthn   bool
	IsPassive    bool
	RequestedACR []string
}

// clockSkew is what we tolerate on IssueInstant in either direction. Real
// deployments have unsynchronised clocks; five minutes is the interoperable
// convention.
const clockSkew = 5 * time.Minute

// ValidateAuthnRequest checks a parsed request against a registered provider.
//
// destination is this IdP's own SSO endpoint URL. now is passed in so the
// caller controls time -- a test that cannot move the clock cannot check
// expiry, and expiry that is never checked is the bug.
func ValidateAuthnRequest(r *AuthnRequest, p *Provider, destination string, now time.Time) (*Validated, error) {
	if !p.Enabled {
		return nil, fmt.Errorf("service provider %q is disabled", p.EntityID)
	}
	if r.ID == "" {
		return nil, fmt.Errorf("AuthnRequest has no ID; the response could not reference it")
	}
	if r.Version != "2.0" {
		return nil, fmt.Errorf("AuthnRequest Version is %q, expected 2.0", r.Version)
	}

	// The Issuer must be the provider we looked up. Checked even though the
	// lookup used it, because a caller could resolve the provider some other way
	// and this is the assertion that the two agree.
	if r.Issuer != p.EntityID {
		return nil, fmt.Errorf("AuthnRequest Issuer %q does not match the provider %q",
			r.Issuer, p.EntityID)
	}

	// Destination, when present, must be US.
	//
	// This is the anti-relay check: without it, a request captured on the way to
	// a different IdP can be replayed here, and the resulting assertion sent
	// somewhere it was never meant to go. The spec makes the attribute optional,
	// so it is enforced only when supplied -- but it is never ignored.
	if r.Destination != "" && !sameURL(r.Destination, destination) {
		return nil, fmt.Errorf("AuthnRequest Destination is %q, but this endpoint is %q",
			r.Destination, destination)
	}

	var issued time.Time
	if r.IssueInstant != "" {
		t, err := time.Parse(time.RFC3339, r.IssueInstant)
		if err != nil {
			return nil, fmt.Errorf("AuthnRequest IssueInstant %q is not a valid timestamp: %w",
				r.IssueInstant, err)
		}
		if d := now.Sub(t); d > clockSkew || d < -clockSkew {
			return nil, fmt.Errorf("AuthnRequest IssueInstant is %s away from now, "+
				"outside the %s tolerance", d.Round(time.Second), clockSkew)
		}
		issued = t
	}
	if issued.IsZero() {
		// Absent is legal. Treat it as "now" so ForceAuthn still terminates:
		// anything else leaves the freshness comparison with nothing to compare
		// against and the flow loops.
		issued = now
	}

	acs, binding, err := resolveACS(r, p)
	if err != nil {
		return nil, err
	}

	format := r.NameIDPolicy.Format
	if format != "" {
		short := shortNameIDFormat(format)
		if short != p.NameIDFormat {
			// Honouring a format the provider is not configured for would let the
			// request choose its own identifier shape -- including asking for the
			// email address of a provider deliberately configured for pairwise
			// identifiers, which is a privacy control the request must not override.
			return nil, fmt.Errorf("AuthnRequest asks for NameID format %q but %q is "+
				"configured for %q", short, p.EntityID, p.NameIDFormat)
		}
	}

	return &Validated{
		RequestID:    r.ID,
		Issuer:       r.Issuer,
		IssueInstant: issued,
		ACSURL:       acs,
		Binding:      binding,
		NameIDFormat: p.NameIDFormat,
		ForceAuthn:   r.ForceAuthn == "true" || r.ForceAuthn == "1",
		IsPassive:    r.IsPassive == "true" || r.IsPassive == "1",
		RequestedACR: r.RequestedAuthnContext.ClassRefs,
	}, nil
}

// resolveACS decides where the assertion may be delivered.
//
// THE most important function in this file. If the request names a URL it must
// be one already registered, matched exactly -- no prefix, no wildcard, no
// "same host is close enough". An attacker who can steer this gets a genuine,
// correctly signed assertion for a real user delivered to their own server.
func resolveACS(r *AuthnRequest, p *Provider) (string, string, error) {
	if len(p.ACSURLs) == 0 {
		return "", "", fmt.Errorf("service provider %q has no registered "+
			"AssertionConsumerService URL", p.EntityID)
	}

	if r.AssertionConsumerServiceURL == "" {
		for _, a := range p.ACSURLs {
			if a.IsDefault {
				return a.URL, a.Binding, nil
			}
		}
		return p.ACSURLs[0].URL, p.ACSURLs[0].Binding, nil
	}

	for _, a := range p.ACSURLs {
		// Exact string comparison. Deliberately NOT a parsed-URL comparison:
		// normalising invites disagreement about case, default ports, trailing
		// slashes and percent-encoding, and every one of those disagreements is a
		// way to satisfy the check with a URL that resolves elsewhere.
		if a.URL == r.AssertionConsumerServiceURL {
			return a.URL, a.Binding, nil
		}
	}
	return "", "", fmt.Errorf("AssertionConsumerServiceURL %q is not registered for %q; "+
		"assertions are only ever delivered to a registered URL",
		r.AssertionConsumerServiceURL, p.EntityID)
}

// sameURL compares two URLs for the Destination check.
//
// Slightly forgiving, and only here: scheme and host are compared
// case-insensitively because both are case-insensitive by definition, while the
// path is compared exactly because it is not. This is a check on OUR OWN
// endpoint, not a decision about where to send anything, so the tolerance
// cannot be turned into a redirect.
func sameURL(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return a == b
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) &&
		strings.EqualFold(ua.Host, ub.Host) &&
		ua.Path == ub.Path
}

// Full URN forms, and the short names used in configuration and the database.
const (
	NameIDFormatPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDFormatTransient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	NameIDFormatEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
)

func shortNameIDFormat(urn string) string {
	switch urn {
	case NameIDFormatPersistent:
		return "persistent"
	case NameIDFormatTransient:
		return "transient"
	case NameIDFormatEmail:
		return "emailAddress"
	default:
		return urn
	}
}

// FullNameIDFormat maps a configured short name to the URN that goes on the wire.
func FullNameIDFormat(short string) string {
	switch short {
	case "persistent":
		return NameIDFormatPersistent
	case "transient":
		return NameIDFormatTransient
	case "emailAddress":
		return NameIDFormatEmail
	default:
		return NameIDFormatUnspecified
	}
}
