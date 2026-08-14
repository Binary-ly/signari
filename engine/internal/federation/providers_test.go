package federation

import "testing"

// TestNoProviderIsTrustedByAccident.
//
// The dangerous direction is a preset that says "believe this provider's
// verified flag" when the provider does not actually verify. Each entry below
// is asserted against the provider's own documented behaviour.
func TestNoProviderIsTrustedByAccident(t *testing.T) {
	cases := []struct {
		kind    Kind
		trusted bool
		why     string
	}{
		{KindGoogle, true,
			"Google's email_verified in the id_token is authoritative"},
		{KindGitHub, false,
			"GET /user returns whatever the user set as public, including unconfirmed addresses"},
		{KindMicrosoft, false,
			"Microsoft documents the email claim as not guaranteed correct and says never to use it for authorization"},
		{KindOIDC, false,
			"an unknown provider's verification means nothing until an operator says it does"},
	}
	for _, c := range cases {
		p, err := PresetFor(c.kind)
		if err != nil {
			t.Fatal(err)
		}
		if p.TrustsEmailVerification != c.trusted {
			t.Errorf("%s: TrustsEmailVerification = %v, want %v -- %s",
				c.kind, p.TrustsEmailVerification, c.trusted, c.why)
		}
	}
}

// TestUntrustedProvidersSayHowToVerify. A provider we do not trust is useless
// for sign-up unless the operator is told what to do about it.
func TestUntrustedProvidersSayHowToVerify(t *testing.T) {
	for _, k := range Kinds() {
		p, _ := PresetFor(k)
		if p.TrustsEmailVerification {
			continue
		}
		if p.Note == "" {
			t.Errorf("%s is not trusted and offers no explanation", k)
		}
	}
}

// TestGitHubIsNotTreatedAsOIDC. GitHub has no id_token; a client that assumes
// one would either crash or, worse, skip verification and carry on.
func TestGitHubIsNotTreatedAsOIDC(t *testing.T) {
	p, _ := PresetFor(KindGitHub)
	if p.OIDC {
		t.Error("GitHub is marked as OIDC; it issues no id_token")
	}
	if !p.EmailNeedsSeparateCheck {
		t.Error("GitHub must be marked as needing a separate email check")
	}
	found := false
	for _, s := range p.Scopes {
		if s == "user:email" {
			found = true
		}
	}
	if !found {
		t.Error("the user:email scope is required to read verified addresses")
	}
}

func TestUnknownKindIsRefused(t *testing.T) {
	if _, err := PresetFor(Kind("facebook")); err == nil {
		t.Error("an unconfigured provider kind was accepted")
	}
}
