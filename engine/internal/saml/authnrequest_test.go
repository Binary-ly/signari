package saml

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const ssoEndpoint = "https://auth.example.com/saml/sso"

func testProvider() *Provider {
	return &Provider{
		ID:       "11111111-1111-1111-1111-111111111111",
		EntityID: "https://sp.example.com/metadata",
		ACSURLs: []ACSURL{
			{URL: "https://sp.example.com/acs", Binding: "HTTP-POST", IsDefault: true},
			{URL: "https://sp.example.com/acs2", Binding: "HTTP-POST"},
		},
		NameIDFormat:    "persistent",
		SignAssertions:  true,
		LifetimeSeconds: 300,
		Enabled:         true,
	}
}

func testRequest() *AuthnRequest {
	return &AuthnRequest{
		ID:           "_abc123",
		Version:      "2.0",
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
		Destination:  ssoEndpoint,
		Issuer:       "https://sp.example.com/metadata",
	}
}

func TestValidAuthnRequest(t *testing.T) {
	v, err := ValidateAuthnRequest(testRequest(), testProvider(), ssoEndpoint, time.Now())
	if err != nil {
		t.Fatalf("a legitimate request was refused: %v", err)
	}
	if v.ACSURL != "https://sp.example.com/acs" {
		t.Errorf("ACSURL = %q, want the registered default", v.ACSURL)
	}
	if v.RequestID != "_abc123" {
		t.Errorf("RequestID = %q", v.RequestID)
	}
}

// TestACSURLMustBeRegistered is the assertion-theft test.
//
// Every entry below is a real technique for making a URL look like it belongs
// to the service provider. If any is accepted, an attacker gets a genuine,
// correctly signed assertion for a real user delivered to a server they own --
// which is a full account takeover at that SP, with nothing invalid anywhere in
// the document.
func TestACSURLMustBeRegistered(t *testing.T) {
	attacks := []struct {
		name, acs string
	}{
		{"outright attacker URL", "https://evil.test/acs"},
		{"attacker host, same path", "https://evil.test/acs"},
		{"registered host as a prefix of the attacker's", "https://sp.example.com.evil.test/acs"},
		{"attacker host with the SP in userinfo", "https://sp.example.com@evil.test/acs"},
		{"subdomain of the registered host", "https://acs.sp.example.com/acs"},
		{"path traversal back out of the registered path", "https://sp.example.com/acs/../../evil"},
		{"trailing slash", "https://sp.example.com/acs/"},
		{"scheme downgraded to http", "http://sp.example.com/acs"},
		{"explicit default port", "https://sp.example.com:443/acs"},
		{"uppercase host", "https://SP.EXAMPLE.COM/acs"},
		{"percent-encoded path", "https://sp.example.com/%61cs"},
		{"query string appended", "https://sp.example.com/acs?next=https://evil.test"},
		{"fragment appended", "https://sp.example.com/acs#@evil.test"},
		{"double slash", "https://sp.example.com//acs"},
		{"backslash instead of slash", "https://sp.example.com\\acs"},
		{"embedded null", "https://sp.example.com/acs\x00.evil.test"},
		{"newline injection", "https://sp.example.com/acs\nhttps://evil.test"},
	}

	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			r := testRequest()
			r.AssertionConsumerServiceURL = a.acs
			v, err := ValidateAuthnRequest(r, testProvider(), ssoEndpoint, time.Now())
			if err == nil {
				t.Fatalf("ACCEPTED %q -> assertion would be delivered to %q",
					a.acs, v.ACSURL)
			}
		})
	}
}

// TestRegisteredACSURLsAreAccepted -- the other direction, so the check above is
// not passing merely by refusing everything.
func TestRegisteredACSURLsAreAccepted(t *testing.T) {
	for _, u := range []string{"https://sp.example.com/acs", "https://sp.example.com/acs2"} {
		r := testRequest()
		r.AssertionConsumerServiceURL = u
		v, err := ValidateAuthnRequest(r, testProvider(), ssoEndpoint, time.Now())
		if err != nil {
			t.Fatalf("registered URL %q was refused: %v", u, err)
		}
		if v.ACSURL != u {
			t.Errorf("ACSURL = %q, want %q", v.ACSURL, u)
		}
	}
}

// TestIssuerMustMatchTheProvider stops one SP from requesting as another.
func TestIssuerMustMatchTheProvider(t *testing.T) {
	r := testRequest()
	r.Issuer = "https://other-sp.example.com/metadata"
	if _, err := ValidateAuthnRequest(r, testProvider(), ssoEndpoint, time.Now()); err == nil {
		t.Fatal("a request issued by a different entity was accepted")
	}
}

// TestDestinationMustBeThisEndpoint is the anti-relay check: a request captured
// en route to another IdP must not be replayable here.
func TestDestinationMustBeThisEndpoint(t *testing.T) {
	r := testRequest()
	r.Destination = "https://other-idp.example.com/sso"
	if _, err := ValidateAuthnRequest(r, testProvider(), ssoEndpoint, time.Now()); err == nil {
		t.Fatal("a request addressed to a different identity provider was accepted")
	}

	// Absent is allowed by the spec, so it must still work.
	r2 := testRequest()
	r2.Destination = ""
	if _, err := ValidateAuthnRequest(r2, testProvider(), ssoEndpoint, time.Now()); err != nil {
		t.Errorf("Destination is optional in the spec but was required: %v", err)
	}

	// Case differences in scheme and host are not meaningful and must not break
	// real deployments.
	r3 := testRequest()
	r3.Destination = "HTTPS://AUTH.EXAMPLE.COM/saml/sso"
	if _, err := ValidateAuthnRequest(r3, testProvider(), ssoEndpoint, time.Now()); err != nil {
		t.Errorf("host case difference was rejected: %v", err)
	}

	// Path case IS meaningful and must not be folded away.
	r4 := testRequest()
	r4.Destination = "https://auth.example.com/SAML/SSO"
	if _, err := ValidateAuthnRequest(r4, testProvider(), ssoEndpoint, time.Now()); err == nil {
		t.Error("a differing path was accepted; paths are case-sensitive")
	}
}

// TestStaleIssueInstantIsRefused. Without this an old request stays valid
// forever, so a captured one can be replayed whenever the attacker likes.
func TestStaleIssueInstantIsRefused(t *testing.T) {
	now := time.Now()
	for _, d := range []time.Duration{-30 * time.Minute, 30 * time.Minute} {
		r := testRequest()
		r.IssueInstant = now.Add(d).UTC().Format(time.RFC3339)
		if _, err := ValidateAuthnRequest(r, testProvider(), ssoEndpoint, now); err == nil {
			t.Errorf("an IssueInstant %s from now was accepted", d)
		}
	}
	// Inside the skew window it must pass, or unsynchronised clocks break logins.
	r := testRequest()
	r.IssueInstant = now.Add(-2 * time.Minute).UTC().Format(time.RFC3339)
	if _, err := ValidateAuthnRequest(r, testProvider(), ssoEndpoint, now); err != nil {
		t.Errorf("a request two minutes old was refused: %v", err)
	}
}

func TestDisabledProviderIsRefused(t *testing.T) {
	p := testProvider()
	p.Enabled = false
	if _, err := ValidateAuthnRequest(testRequest(), p, ssoEndpoint, time.Now()); err == nil {
		t.Fatal("a disabled provider still received an assertion")
	}
}

func TestProviderWithNoACSIsRefused(t *testing.T) {
	p := testProvider()
	p.ACSURLs = nil
	if _, err := ValidateAuthnRequest(testRequest(), p, ssoEndpoint, time.Now()); err == nil {
		t.Fatal("a provider with nowhere to deliver to was accepted")
	}
}

// TestNameIDPolicyCannotOverrideTheProvider. A provider configured for pairwise
// persistent identifiers must not be talked into emitting the email address --
// that is a privacy decision made at registration, not per request.
func TestNameIDPolicyCannotOverrideTheProvider(t *testing.T) {
	r := testRequest()
	r.NameIDPolicy.Format = NameIDFormatEmail
	_, err := ValidateAuthnRequest(r, testProvider(), ssoEndpoint, time.Now())
	if err == nil {
		t.Fatal("a request talked a persistent-format provider into emailAddress")
	}
	if !strings.Contains(err.Error(), "persistent") {
		t.Errorf("error should say what is configured; got %v", err)
	}

	// Asking for the configured format is fine.
	r2 := testRequest()
	r2.NameIDPolicy.Format = NameIDFormatPersistent
	if _, err := ValidateAuthnRequest(r2, testProvider(), ssoEndpoint, time.Now()); err != nil {
		t.Errorf("asking for the configured format was refused: %v", err)
	}
}

func TestVersionAndIDAreRequired(t *testing.T) {
	r := testRequest()
	r.Version = "1.1"
	if _, err := ValidateAuthnRequest(r, testProvider(), ssoEndpoint, time.Now()); err == nil {
		t.Error("a SAML 1.1 request was accepted by a 2.0 endpoint")
	}
	r2 := testRequest()
	r2.ID = ""
	if _, err := ValidateAuthnRequest(r2, testProvider(), ssoEndpoint, time.Now()); err == nil {
		t.Error("a request with no ID was accepted; the response could not reference it")
	}
}

// TestEndToEndDecodeAndValidate runs a request through the real wire format,
// because the decoder and the validator have to agree about what they hand each
// other -- and a test that constructs the struct directly never checks that.
func TestEndToEndDecodeAndValidate(t *testing.T) {
	xmlDoc := fmt.Sprintf(`<samlp:AuthnRequest
		xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
		ID="_wire1" Version="2.0" IssueInstant="%s"
		Destination="%s"
		AssertionConsumerServiceURL="https://sp.example.com/acs">
		<saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
	</samlp:AuthnRequest>`, time.Now().UTC().Format(time.RFC3339), ssoEndpoint)

	raw, err := DecodeRedirect(deflate64(t, xmlDoc))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var r AuthnRequest
	if err := Unmarshal(raw, &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	v, err := ValidateAuthnRequest(&r, testProvider(), ssoEndpoint, time.Now())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if v.ACSURL != "https://sp.example.com/acs" || v.RequestID != "_wire1" {
		t.Errorf("validated = %+v", v)
	}
}

// TestCommentTruncationInIssuer joins the two defences: a comment inside the
// Issuer would otherwise let the parsed entity id differ from the signed one.
func TestCommentTruncationInIssuer(t *testing.T) {
	xmlDoc := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
		ID="_c1" Version="2.0">
		<saml:Issuer>https://sp.example.com/metadata<!---->.evil.test</saml:Issuer>
	</samlp:AuthnRequest>`
	var r AuthnRequest
	if err := Unmarshal([]byte(xmlDoc), &r); err == nil {
		t.Fatalf("a commented Issuer parsed to %q instead of being refused", r.Issuer)
	}
}
