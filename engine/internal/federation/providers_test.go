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
		// True for both, and NOT because these providers are honest -- because
		// this package does extra work for each. GitHub's verified flag is read
		// from /user/emails rather than /user; Microsoft's comes from xms_edov
		// rather than email_verified. The flag describes what we produce.
		{KindGitHub, true,
			"we read /user/emails, so the value we produce is a confirmed address"},
		{KindMicrosoft, true,
			"we read xms_edov and ignore email_verified, so a verified value means the domain owner was verified"},
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

// TestEveryProviderExplainsItsPolicy. Trusted or not, an operator choosing a
// provider has to be told how verification is established -- it decides whether
// sign-up works at all, and it cannot be discovered from the provider's console.
func TestEveryProviderExplainsItsPolicy(t *testing.T) {
	for _, k := range Kinds() {
		p, _ := PresetFor(k)
		if p.Note == "" {
			t.Errorf("%s offers no explanation of its verification policy", k)
		}
	}
}

// TestTrustEarnedBySeparateCheckIsMarkedAsSuch.
//
// Where trust comes from extra work rather than an honest response, that must be
// recorded -- otherwise somebody simplifying the client later removes the
// /user/emails call and leaves the provider marked trusted.
func TestTrustEarnedBySeparateCheckIsMarkedAsSuch(t *testing.T) {
	for _, k := range []Kind{KindGitHub, KindMicrosoft} {
		p, _ := PresetFor(k)
		if !p.TrustsEmailVerification {
			t.Errorf("%s should be trusted -- the client does the work to earn it", k)
		}
		if !p.EmailNeedsSeparateCheck {
			t.Errorf("%s is trusted only because of a separate check, which is not recorded", k)
		}
	}
	// Google needs no extra work; Google's own flag is authoritative.
	g, _ := PresetFor(KindGoogle)
	if g.EmailNeedsSeparateCheck {
		t.Error("Google is marked as needing a separate check; its id_token flag is authoritative")
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
