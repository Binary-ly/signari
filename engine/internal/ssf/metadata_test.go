package ssf

import (
	"encoding/json"
	"strings"
	"testing"
)

// §7.1: "If absent, the Transmitter is assumed to conform to "1_0-ID1" version
// of the specification."
//
// Silence is not neutral here. A Final-conformant transmitter that omits
// spec_version is read as an implementer's draft, so the field has to be present
// AND has to say 1_0.
func TestSpecVersionSaysFinalNotDraft(t *testing.T) {
	md := Metadata("https://idp.example", "https://idp.example/oauth2/jwks")
	if md.SpecVersion != "1_0" {
		t.Errorf("spec_version = %q, want \"1_0\"; absent or wrong means a receiver "+
			"assumes 1_0-ID1, an implementer's draft", md.SpecVersion)
	}
	// And it must survive serialisation — a field that marshals away is absent.
	b, err := json.Marshal(md)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"spec_version":"1_0"`) {
		t.Errorf("spec_version did not serialise: %s", b)
	}
}

// §7.1: jwks_uri "MUST be specified if the Transmitter intends to generate
// signed JWTs."
//
// We sign every SET, so for this transmitter the OPTIONAL field is required.
func TestJWKSURIIsPublishedBecauseWeSign(t *testing.T) {
	md := Metadata("https://idp.example", "https://idp.example/oauth2/jwks")
	if md.JWKSURI == "" {
		t.Fatal("jwks_uri is empty; §7.1 requires it of any transmitter that " +
			"generates signed JWTs, and every SET we emit is signed")
	}
	b, _ := json.Marshal(md)
	if !strings.Contains(string(b), `"jwks_uri"`) {
		t.Errorf("jwks_uri did not serialise: %s", b)
	}
}

// §7.1: the issuer "MUST be identical to the iss claim value in Security Event
// Tokens issued from this Transmitter."
//
// Reported verbatim, including a development http issuer. Tidying it to https
// would satisfy the sentence about the scheme by breaking this one — and §4.1.6
// makes receivers reject any SET whose iss does not match, so a "corrected"
// document would make us unsubscribable rather than more secure.
func TestTheIssuerIsReportedVerbatim(t *testing.T) {
	for _, iss := range []string{
		"https://idp.example",
		"http://localhost:8080",
		"https://tr.example.com/issuer1",
	} {
		if got := Metadata(iss, iss+"/oauth2/jwks").Issuer; got != iss {
			t.Errorf("issuer = %q, want %q verbatim: the document must agree with "+
				"the `iss` we actually sign, which §4.1.6 makes receivers enforce",
				got, iss)
		}
	}
}

// Endpoints we do not implement must be ABSENT, not empty.
//
// §8's management endpoints are how a receiver discovers it can self-serve. An
// empty string for configuration_endpoint is still a present key, and a receiver
// reading the document sees a transmitter offering something that is not there.
func TestUnimplementedEndpointsAreOmittedEntirely(t *testing.T) {
	b, err := json.Marshal(Metadata("https://idp.example", "https://idp.example/oauth2/jwks"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{
		"configuration_endpoint", "status_endpoint", "add_subject_endpoint",
		"remove_subject_endpoint", "verification_endpoint", "authorization_schemes",
	} {
		if v, present := doc[k]; present {
			t.Errorf("%s is present (%v) but this engine has no management API; "+
				"advertising an endpoint that 404s is worse than advertising "+
				"nothing, because the receiver's next move is to call it", k, v)
		}
	}
}

// §7.1: default_subjects, "If present, the value MUST be either "ALL" or "NONE"".
//
// Ours is neither — a stream carries events about the subjects that client has
// actually seen. Omitting is explicitly conformant ("If not provided, the
// Transmitter behavior in this regard is unspecified"); emitting a third value
// would violate a MUST, and emitting either legal value would be a lie.
func TestDefaultSubjectsIsOmittedRatherThanGuessed(t *testing.T) {
	md := Metadata("https://idp.example", "https://idp.example/oauth2/jwks")
	if md.DefaultSubjects == "" {
		return // omitted, which is what we want
	}
	if md.DefaultSubjects != "ALL" && md.DefaultSubjects != "NONE" {
		t.Errorf("default_subjects = %q; §7.1 permits only \"ALL\" or \"NONE\", "+
			"so a third value breaks a MUST", md.DefaultSubjects)
	}
}

// §6.1.1 / §6.1.2: the delivery method URIs are exact strings a receiver matches on.
func TestDeliveryMethodsAreTheSpecifiedURIs(t *testing.T) {
	if DeliveryPush != "urn:ietf:rfc:8935" {
		t.Errorf("push URI = %q, want urn:ietf:rfc:8935", DeliveryPush)
	}
	if DeliveryPoll != "urn:ietf:rfc:8936" {
		t.Errorf("poll URI = %q, want urn:ietf:rfc:8936", DeliveryPoll)
	}
	md := Metadata("https://idp.example", "https://idp.example/oauth2/jwks")
	// The engine now implements both, so both are advertised -- and only these
	// two. A method appears here once its endpoint works.
	want := map[string]bool{DeliveryPush: true, DeliveryPoll: true}
	if len(md.DeliveryMethodsSupported) != len(want) {
		t.Fatalf("delivery_methods_supported = %v; want push and poll",
			md.DeliveryMethodsSupported)
	}
	for _, m := range md.DeliveryMethodsSupported {
		if !want[m] {
			t.Errorf("delivery_methods_supported advertises %q, which is not implemented", m)
		}
		delete(want, m)
	}
	for m := range want {
		t.Errorf("delivery_methods_supported is missing %q, which is implemented", m)
	}
}

// §7.2.1: where the document lives when the issuer has a path component.
//
//	"If the Issuer value contains a path component, any terminating "/" MUST be
//	removed before inserting "/.well-known/ssf-configuration" between the host
//	component and the path component."
//
// A transmitter serving only the bare path is undiscoverable in exactly the
// multi-tenant deployments this rule exists for.
func TestWellKnownPathFollowsTheIssuerPath(t *testing.T) {
	for _, tc := range []struct{ issuer, want string }{
		{"https://tr.example.com", "/.well-known/ssf-configuration"},
		{"https://tr.example.com/", "/.well-known/ssf-configuration"},
		{"https://tr.example.com/issuer1", "/.well-known/ssf-configuration/issuer1"},
		{"https://tr.example.com/issuer1/", "/.well-known/ssf-configuration/issuer1"},
		{"https://tr.example.com/a/b", "/.well-known/ssf-configuration/a/b"},
	} {
		if got := WellKnownPath(tc.issuer); got != tc.want {
			t.Errorf("WellKnownPath(%q) = %q, want %q", tc.issuer, got, tc.want)
		}
	}
}
