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
	// The context is derived from the methods actually used (amr), never from a
	// stored acr: a row that claims multi-factor without the methods to show for
	// it is not evidence.
	cases := []struct {
		name string
		amr  []string
		want string
	}{
		{"password only", []string{oauth.AMRPassword}, saml.AuthnContextPassword},
		{"no context at all", nil, saml.AuthnContextPassword},
		{"presence alone is not a factor", []string{oauth.AMRUserPresence}, saml.AuthnContextPassword},
		// The case this was wrong about: a passkey used without user
		// verification is one factor, and must not satisfy an SP's step-up.
		{"hardware key alone, no user verification", []string{oauth.AMRHardwareKey, oauth.AMRUserPresence},
			saml.AuthnContextPassword},
		{"password plus otp", []string{oauth.AMRPassword, oauth.AMROTP}, saml.AuthnContextMFA},
		{"password plus hardware key", []string{oauth.AMRPassword, oauth.AMRHardwareKey}, saml.AuthnContextMFA},
		{"hardware key with user verification", []string{oauth.AMRHardwareKey, oauth.AMRPIN}, saml.AuthnContextMFA},
		{"amr says mfa", []string{oauth.AMRMFA}, saml.AuthnContextMFA},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := samlAuthnContext(c.amr); got != c.want {
				t.Errorf("samlAuthnContext(%v) = %q, want %q", c.amr, got, c.want)
			}
		})
	}
}
