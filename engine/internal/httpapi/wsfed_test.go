package httpapi

import (
	"errors"
	"testing"

	"signari.dev/engine/internal/saml"
)

// `/wsfed` is a registered route in two methods and carried no test at all until
// this one. That is worth stating rather than quietly fixing: it is an
// authentication endpoint that issues a signed SAML assertion, and the only thing
// standing between a link and that assertion being delivered somewhere the
// operator never registered is `wsFedDestination`.
//
// WS-Federation 1.2 §13.2.3 makes `wreply` optional and says the token is
// returned to "the resource" — it does not tell an implementer to validate the
// parameter, because in 2003 the threat was not on the reading list. An
// implementation that takes `wreply` at its word is an open redirector that
// delivers credentials.
func TestWSFedRefusesAnUnregisteredWReply(t *testing.T) {
	p := &saml.Provider{ACSURLs: []saml.ACSURL{
		{URL: "https://app.example/wsfed", IsDefault: true},
		{URL: "https://app.example/alternate", IsDefault: false},
	}}

	for _, reply := range []string{
		"https://attacker.example/collect",
		// Prefix games, because the comment on the matcher says exactly-only and
		// a prefix match "is how a redirector is built by accident".
		"https://app.example/wsfed.attacker.example",
		"https://app.example/wsfed/../../../evil",
		"https://app.example/wsfed?next=https://attacker.example",
		"https://app.example/wsfed#@attacker.example",
		// Case and trailing slash: both are different URLs, and "close enough"
		// is the whole failure mode.
		"https://APP.example/wsfed",
		"https://app.example/wsfed/",
	} {
		got, err := wsFedDestination(p, reply)
		if err == nil {
			t.Errorf("wreply %q was accepted and resolved to %q; a signed assertion "+
				"would be posted there", reply, got)
		}
		if !errors.Is(err, errWReplyUnregistered) && err != errWReplyUnregistered {
			t.Errorf("wreply %q refused with %v, want errWReplyUnregistered", reply, err)
		}
	}
}

// The other half: a registered reply URL must still work, including the
// non-default one. A guard that refuses everything is not a guard, it is an
// outage, and this is the assertion that tells the two apart.
func TestWSFedAcceptsEveryRegisteredReply(t *testing.T) {
	p := &saml.Provider{ACSURLs: []saml.ACSURL{
		{URL: "https://app.example/wsfed", IsDefault: true},
		{URL: "https://app.example/alternate", IsDefault: false},
	}}
	for _, reply := range []string{"https://app.example/wsfed", "https://app.example/alternate"} {
		got, err := wsFedDestination(p, reply)
		if err != nil {
			t.Errorf("registered wreply %q was refused: %v", reply, err)
		}
		if got != reply {
			t.Errorf("wreply %q resolved to %q", reply, got)
		}
	}
}

// No wreply is the ordinary case and must resolve to the URL the operator marked
// default -- not merely to the first one, which would make the default flag
// decorative and silently change where assertions go when the list is reordered.
func TestWSFedWithoutAWReplyUsesTheDefaultNotTheFirst(t *testing.T) {
	p := &saml.Provider{ACSURLs: []saml.ACSURL{
		{URL: "https://app.example/first", IsDefault: false},
		{URL: "https://app.example/the-default", IsDefault: true},
	}}
	got, err := wsFedDestination(p, "")
	if err != nil {
		t.Fatalf("no wreply should use the default ACS URL: %v", err)
	}
	if got != "https://app.example/the-default" {
		t.Errorf("resolved to %q, want the URL flagged default; the flag is not "+
			"decorative and reordering the list must not move where assertions go", got)
	}
}

// An application with no reply URL at all must fail rather than resolve to "".
// An empty destination is a POST to the current page, which is neither a refusal
// nor a delivery.
func TestWSFedWithNoRegisteredReplyURLFails(t *testing.T) {
	if got, err := wsFedDestination(&saml.Provider{}, ""); err == nil {
		t.Fatalf("a provider with no ACS URL resolved to %q instead of failing", got)
	}
}
