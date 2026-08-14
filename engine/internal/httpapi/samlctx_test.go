package httpapi

import (
	"testing"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/saml"
)

// TestSAMLAuthnContextDoesNotOverstate.
//
// A service provider gates access on this value. Claiming multi-factor for a
// password-only session tells it a step-up requirement was met when it was not,
// which is a security decision made on a false premise.
//
// The original implementation returned MFA for any acr other than "0" -- and a
// password-only session carries acr "1", so every ordinary login claimed
// multi-factor. Nothing in the code review caught it; comparing a live
// assertion against the session row that produced it did.
func TestSAMLAuthnContextDoesNotOverstate(t *testing.T) {
	cases := []struct {
		name string
		acr  string
		amr  []string
		want string
	}{
		{"password only", oauth.ACRSingleFactor, []string{oauth.AMRPassword}, saml.AuthnContextPassword},
		{"no context at all", "", nil, saml.AuthnContextPassword},
		{"passkey used alone is still one factor", oauth.ACRSingleFactor,
			[]string{oauth.AMRUserPresence}, saml.AuthnContextPassword},
		{"password plus otp", oauth.ACRMultiFactor,
			[]string{oauth.AMRPassword, oauth.AMROTP}, saml.AuthnContextMFA},
		{"hardware key", oauth.ACRMultiFactor,
			[]string{oauth.AMRPassword, oauth.AMRHardwareKey}, saml.AuthnContextMFA},
		{"amr says mfa even if acr lags", oauth.ACRSingleFactor,
			[]string{oauth.AMRMFA}, saml.AuthnContextMFA},
		{"PAPE spelling of multi-factor", oauth.ACRPapeMultiFactor,
			[]string{oauth.AMRPassword}, saml.AuthnContextMFA},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := samlAuthnContext(c.acr, c.amr); got != c.want {
				t.Errorf("samlAuthnContext(%q, %v) = %q, want %q", c.acr, c.amr, got, c.want)
			}
		})
	}
}
