package saml

import (
	"strings"
	"testing"
	"time"
)

func TestARequestedClassIsARung(t *testing.T) {
	const password, unknown = AuthnContextPassword, "urn:example:retina-scan"
	for _, tc := range []struct {
		name       string
		classes    []string
		comparison string
		rung       int
		reachable  bool
	}{
		{"nothing asked", nil, "", 0, true},
		{"a password", []string{password}, "", 1, true},
		{"a second factor", []string{AuthnContextMFA}, "", 2, true},
		{"minimum is a floor", []string{AuthnContextMFA}, "minimum", 2, true},
		{"any of them will do", []string{AuthnContextMFA, password}, "exact", 1, true},
		{"one known is enough", []string{unknown, AuthnContextMFA}, "", 2, true},
		{"nothing known", []string{unknown}, "", 0, false},
		{"better than a password", []string{password}, "better", 2, true},
		{"better than a second factor", []string{AuthnContextMFA}, "better", 3, false},
		{"maximum forces nothing", []string{AuthnContextMFA}, "maximum", 0, true},
		{"nothing known, whatever the comparison", []string{unknown}, "maximum", 0, false},
	} {
		if rung, reachable := RequestedRung(tc.classes, tc.comparison); rung != tc.rung || reachable != tc.reachable {
			t.Errorf("%s: rung %d reachable %t, want %d %t", tc.name, rung, reachable, tc.rung, tc.reachable)
		}
	}
}

// Audience and timing say who an assertion is for and when, and neither says where it
// may be presented. Each of these is correctly signed for this audience, so only the
// confirmation stops it.
func TestAnAssertionIsPresentedOnlyWhereItIsConfirmedFor(t *testing.T) {
	u := newUpstream(t)
	const elsewhere = "https://other-sp.test/saml/acs"
	const holderOfKey = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
	p := inboundProvider(u)
	for name, tc := range map[string]struct {
		confirmations []confirmation
		want          string // Empty is accepted.
	}{
		"another service provider's ACS": {[]confirmation{{method: bearerMethod, recipient: elsewhere}}, "confirmed for"},
		"no Recipient":                   {[]confirmation{{method: bearerMethod}}, "confirmed for"},
		"no bearer confirmation":         {[]confirmation{{method: holderOfKey, recipient: p.ACSURL}}, "no bearer confirmation"},
		"no confirmation data":           {[]confirmation{{method: bearerMethod, noData: true}}, "no SubjectConfirmationData"},
		"no expiry":                      {[]confirmation{{method: bearerMethod, recipient: p.ACSURL, noExpiry: true}}, "NotOnOrAfter"},
		"ours is the second": {[]confirmation{{method: bearerMethod, recipient: elsewhere},
			{method: bearerMethod, recipient: p.ACSURL}}, ""},
		"a method beside ours": {[]confirmation{{method: holderOfKey},
			{method: bearerMethod, recipient: p.ACSURL}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			raw := u.response(t, respOpts{inResponseTo: "_req-1", destination: p.ACSURL, signAssertion: true,
				confirmations: tc.confirmations})
			got, err := ConsumeResponse(raw, p, ConsumeOptions{ExpectedInResponseTo: "_req-1", Destination: p.ACSURL,
				Now: time.Now()})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted, signing in %q", got.Subject)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}
}
