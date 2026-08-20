package ssf

import (
	"net/url"
	"strings"
)

// Delivery method URIs (§6.1.1, §6.1.2).
//
// The values are the specification's, verbatim. A receiver matches on these
// strings to decide whether it can talk to us at all, so a near-miss is a
// transmitter nobody can subscribe to.
const (
	DeliveryPush = "urn:ietf:rfc:8935"
	DeliveryPoll = "urn:ietf:rfc:8936"
)

// SpecVersion is what we advertise in the transmitter configuration.
//
// §7.1 makes this OPTIONAL with a consequential default:
//
//	"If absent, the Transmitter is assumed to conform to "1_0-ID1" version of
//	the specification."
//
// 1_0-ID1 is an implementer's draft. Omitting this field does not mean "version
// unspecified", it means "assume I am the draft" -- so a Final-conformant
// transmitter that says nothing is understood to be something else. We publish
// it for that reason alone.
const SpecVersion = "1_0"

// TransmitterMetadata is the §7.1 transmitter configuration document.
//
// Every field this engine cannot honour is omitted rather than emitted empty.
// That is not tidiness: the OPTIONAL management endpoints are how a receiver
// discovers what a transmitter can do, and advertising a configuration endpoint
// that 404s is worse than advertising nothing, because the receiver's next step
// is to use it.
//
// It is the same rule this project applied to OIDC discovery after advertising
// three endpoints that did not exist: a capability enters a discovery document
// once it works.
type TransmitterMetadata struct {
	SpecVersion string `json:"spec_version"`
	Issuer      string `json:"issuer"`
	JWKSURI     string `json:"jwks_uri"`

	DeliveryMethodsSupported []string `json:"delivery_methods_supported,omitempty"`

	// The management API endpoints (§8) are all OPTIONAL and all absent here:
	// this engine's streams are administered by its operator, not configured
	// over HTTP by receivers. Their absence is the honest signal that a
	// receiver cannot self-serve.
	ConfigurationEndpoint string `json:"configuration_endpoint,omitempty"`
	StatusEndpoint        string `json:"status_endpoint,omitempty"`
	AddSubjectEndpoint    string `json:"add_subject_endpoint,omitempty"`
	RemoveSubjectEndpoint string `json:"remove_subject_endpoint,omitempty"`
	VerificationEndpoint  string `json:"verification_endpoint,omitempty"`

	CriticalSubjectMembers []string `json:"critical_subject_members,omitempty"`
	DefaultSubjects        string   `json:"default_subjects,omitempty"`

	// AuthorizationSchemes (§7.1.1) describes how a receiver authenticates to
	// the management API. With no management API there is nothing to describe.
	AuthorizationSchemes []map[string]any `json:"authorization_schemes,omitempty"`
}

// Metadata builds the transmitter configuration for an issuer.
//
// # The issuer is reported exactly as configured
//
// §7.1 says the issuer is "URL using the https scheme" and -- the part that
// governs here -- "MUST be identical to the iss claim value in Security Event
// Tokens issued from this Transmitter".
//
// So this returns the configured issuer verbatim, including when a development
// deployment has set an http one. Publishing a tidied-up https variant of an
// issuer we actually sign with would satisfy the sentence about the scheme by
// breaking the sentence about the `iss` claim, and it is the second that a
// receiver enforces: §4.1.6 requires it to reject any SET whose `iss` does not
// match the stream configuration. A metadata document that disagrees with our
// own signatures makes us unsubscribable.
//
// An http issuer in production is a deployment fault, and the receiver is the
// party the specification puts in charge of noticing -- §7.2: "Receivers SHOULD
// ensure that the Issuer URL comes from a trusted source and uses the https
// scheme."
func Metadata(issuer, jwksURI string) TransmitterMetadata {
	return TransmitterMetadata{
		SpecVersion:              SpecVersion,
		Issuer:                   issuer,
		JWKSURI:                  jwksURI,
		DeliveryMethodsSupported: []string{DeliveryPush},

		// default_subjects is deliberately absent.
		//
		// §7.1 permits exactly two values -- "If present, the value MUST be
		// either "ALL" or "NONE"" -- and this engine is neither. A stream here
		// carries events about the subjects that client has actually seen,
		// which is narrower than ALL and wider than NONE.
		//
		// Omitting is conformant: "If not provided, the Transmitter behavior in
		// this regard is unspecified." Claiming ALL would promise events about
		// every user in the directory, and claiming NONE would tell a receiver
		// it must add subjects through an endpoint we do not offer. Both are
		// worse than saying nothing.
	}
}

// WellKnownPath returns where §7.2 requires this document to be served.
//
//	"Transmitters supporting Discovery MUST make a JSON document available at
//	the path formed by inserting the string "/.well-known/ssf-configuration"
//	into the Issuer between the host component and the path component, if any."
//
// The "if any" is the whole reason this function exists. For an issuer with no
// path it is simply /.well-known/ssf-configuration, and that is what almost
// every implementation hard-codes. For an issuer of https://tr.example.com/issuer1
// the document belongs at /.well-known/ssf-configuration/issuer1 -- §7.2.1 --
// and a transmitter serving only the bare path is undiscoverable in exactly the
// multi-tenant deployments the rule exists for.
//
//	"If the Issuer value contains a path component, any terminating "/" MUST be
//	removed before inserting "/.well-known/ssf-configuration" between the host
//	component and the path component."
const WellKnownBase = "/.well-known/ssf-configuration"

func WellKnownPath(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return WellKnownBase
	}
	p := strings.TrimSuffix(u.Path, "/")
	if p == "" {
		return WellKnownBase
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return WellKnownBase + p
}
