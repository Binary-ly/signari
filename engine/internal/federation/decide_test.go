package federation

import (
	"strings"
	"testing"
)

func trusting() Policy {
	return Policy{
		AllowSignup: true, AllowLinking: true,
		RequireVerifiedEmail: true, TrustsEmailVerification: true,
	}
}

// TestEmailAloneNeverLinksAnAccount is the test this package exists for.
//
// Each case is the takeover: an attacker holds an external account carrying the
// victim's address, and a local account with that address already exists. Any
// outcome that signs them in as the victim, or attaches their external account
// to the victim's, is a full account takeover with no credential of the
// victim's involved.
func TestEmailAloneNeverLinksAnAccount(t *testing.T) {
	victim := "victim-user-id"

	cases := []struct {
		name string
		ext  ExternalIdentity
		p    Policy
	}{
		{
			name: "unverified email matching a local account",
			ext:  ExternalIdentity{Subject: "attacker-sub", Email: "victim@example.com"},
			p:    trusting(),
		},
		{
			name: "provider CLAIMS the email is verified",
			ext: ExternalIdentity{Subject: "attacker-sub", Email: "victim@example.com",
				EmailVerified: true},
			p: trusting(),
		},
		{
			name: "provider claims verified and we trust its verification",
			ext: ExternalIdentity{Subject: "attacker-sub", Email: "victim@example.com",
				EmailVerified: true},
			p: Policy{AllowSignup: true, AllowLinking: true,
				RequireVerifiedEmail: true, TrustsEmailVerification: true},
		},
		{
			name: "verification not required at all",
			ext: ExternalIdentity{Subject: "attacker-sub", Email: "victim@example.com",
				EmailVerified: true},
			p: Policy{AllowSignup: true, AllowLinking: true,
				RequireVerifiedEmail: false, TrustsEmailVerification: true},
		},
		{
			name: "same display name as well",
			ext: ExternalIdentity{Subject: "attacker-sub", Email: "victim@example.com",
				EmailVerified: true, Name: "The Victim"},
			p: trusting(),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := Decide(c.ext, c.p, Context{LocalUserWithSameEmail: victim})
			if err != nil {
				t.Fatal(err)
			}
			if d.Outcome == SignIn {
				t.Fatalf("SIGNED IN as %q on a matching email alone -- full account takeover", d.UserID)
			}
			if d.Outcome == LinkToCurrentUser {
				t.Fatalf("LINKED to %q with nobody signed in -- full account takeover", d.UserID)
			}
			if d.UserID == victim {
				t.Fatalf("the decision names the victim's account (%s)", d.UserID)
			}
			if d.Outcome != RequireLocalSignIn && d.Outcome != Refuse {
				t.Fatalf("outcome = %v, want a refusal", d.Outcome)
			}
			// And the person on the other end has to be told what to do.
			if !strings.Contains(strings.ToLower(d.Reason), "sign in") &&
				!strings.Contains(strings.ToLower(d.Reason), "administrator") {
				t.Errorf("the reason does not tell the user what to do next: %q", d.Reason)
			}
		})
	}
}

// TestKnownSubjectSignsIn -- the ordinary returning user.
func TestKnownSubjectSignsIn(t *testing.T) {
	d, err := Decide(
		ExternalIdentity{Subject: "sub-123", Email: "alice@example.com", EmailVerified: true},
		trusting(),
		Context{ExistingLinkUserID: "alice-id"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if d.Outcome != SignIn || d.UserID != "alice-id" {
		t.Fatalf("got %v/%q, want sign in as alice-id", d.Outcome, d.UserID)
	}
}

// TestKnownSubjectWinsOverAMatchingEmail.
//
// Ordering matters: if the email check ran first, an attacker who got a local
// account created with the victim's address could block the victim's own
// federated sign-in. The established link is authoritative.
func TestKnownSubjectWinsOverAMatchingEmail(t *testing.T) {
	d, _ := Decide(
		ExternalIdentity{Subject: "sub-123", Email: "alice@example.com", EmailVerified: true},
		trusting(),
		Context{ExistingLinkUserID: "alice-id", LocalUserWithSameEmail: "someone-else"},
	)
	if d.Outcome != SignIn || d.UserID != "alice-id" {
		t.Fatalf("got %v/%q, want the established link to win", d.Outcome, d.UserID)
	}
}

// TestLinkingRequiresBothAnIntentAndASession.
//
// The link path is the only one that attaches an external account to an
// existing local one, so it must be unreachable without a local session AND an
// explicit request recorded when the flow began.
func TestLinkingRequiresBothAnIntentAndASession(t *testing.T) {
	ext := ExternalIdentity{Subject: "new-sub", Email: "alice@example.com", EmailVerified: true}

	// Both present: allowed.
	d, _ := Decide(ext, trusting(), Context{LinkRequested: true, CurrentUserID: "alice-id"})
	if d.Outcome != LinkToCurrentUser || d.UserID != "alice-id" {
		t.Fatalf("got %v, want a link to alice-id", d.Outcome)
	}

	// Intent without a session: an attacker adding a parameter to the callback.
	d, _ = Decide(ext, trusting(), Context{LinkRequested: true})
	if d.Outcome == LinkToCurrentUser {
		t.Error("linked with nobody signed in")
	}

	// Session without intent: a signed-in user who came through the plain
	// sign-in button must not silently acquire a link.
	d, _ = Decide(ext, trusting(), Context{CurrentUserID: "alice-id"})
	if d.Outcome == LinkToCurrentUser {
		t.Error("linked without the user asking to")
	}
}

// TestLinkingCanBeDisabled.
func TestLinkingCanBeDisabled(t *testing.T) {
	p := trusting()
	p.AllowLinking = false
	d, _ := Decide(
		ExternalIdentity{Subject: "new-sub", Email: "a@example.com", EmailVerified: true},
		p, Context{LinkRequested: true, CurrentUserID: "alice-id"})
	if d.Outcome == LinkToCurrentUser {
		t.Error("linked despite the provider forbidding it")
	}
}

// TestNewUserIsCreatedWhenAllowed.
func TestNewUserIsCreatedWhenAllowed(t *testing.T) {
	d, err := Decide(
		ExternalIdentity{Subject: "brand-new", Email: "new@example.com", EmailVerified: true},
		trusting(), Context{})
	if err != nil {
		t.Fatal(err)
	}
	if d.Outcome != CreateUser {
		t.Fatalf("outcome = %v, want CreateUser", d.Outcome)
	}
}

func TestSignupCanBeDisabled(t *testing.T) {
	p := trusting()
	p.AllowSignup = false
	d, _ := Decide(
		ExternalIdentity{Subject: "brand-new", Email: "new@example.com", EmailVerified: true},
		p, Context{})
	if d.Outcome != Refuse {
		t.Fatalf("outcome = %v, want Refuse", d.Outcome)
	}
}

// TestUnverifiedEmailCannotCreateAnAccount.
//
// Creating an account with an unverified address is how the NEXT person's
// takeover is set up: the attacker registers first, holding an address they do
// not own, and the real owner arrives to find it taken.
func TestUnverifiedEmailCannotCreateAnAccount(t *testing.T) {
	d, _ := Decide(
		ExternalIdentity{Subject: "brand-new", Email: "someone@example.com", EmailVerified: false},
		trusting(), Context{})
	if d.Outcome == CreateUser {
		t.Fatal("created an account from an unverified email address")
	}
}

// TestUntrustedProviderVerificationIsNotBelieved.
//
// GitHub returns an address the user never confirmed unless asked otherwise.
// A provider whose verification means nothing must not have its flag believed
// just because the flag is set.
func TestUntrustedProviderVerificationIsNotBelieved(t *testing.T) {
	p := trusting()
	p.TrustsEmailVerification = false

	d, _ := Decide(
		ExternalIdentity{Subject: "brand-new", Email: "new@example.com", EmailVerified: true},
		p, Context{})
	if d.Outcome == CreateUser {
		t.Fatal("believed a verified flag from a provider whose verification is not trusted")
	}

	email, verified := EmailToRecord(
		ExternalIdentity{Subject: "s", Email: "new@example.com", EmailVerified: true}, p)
	if verified {
		t.Error("recorded the address as verified on an untrusted provider's say-so")
	}
	if email != "new@example.com" {
		t.Error("the address should still be kept for display and support")
	}
}

// TestMissingSubjectIsRefused. Without a stable identifier the only thing left
// to match on is the email, which is the bug.
func TestMissingSubjectIsRefused(t *testing.T) {
	d, err := Decide(
		ExternalIdentity{Email: "alice@example.com", EmailVerified: true},
		trusting(), Context{ExistingLinkUserID: "alice-id"})
	if err == nil {
		t.Fatal("accepted an identity with no subject")
	}
	if d.Outcome != Refuse {
		t.Errorf("outcome = %v, want Refuse", d.Outcome)
	}
}

// TestEveryOutcomeIsReachable guards against a refactor that quietly makes a
// branch unreachable -- a decision function that can only ever refuse would
// pass every security test above.
func TestEveryOutcomeIsReachable(t *testing.T) {
	seen := map[Outcome]bool{}
	inputs := []struct {
		ext ExternalIdentity
		p   Policy
		c   Context
	}{
		{ExternalIdentity{Subject: "s"}, trusting(), Context{ExistingLinkUserID: "u"}},
		{ExternalIdentity{Subject: "s", Email: "a@b.c", EmailVerified: true}, trusting(), Context{}},
		{ExternalIdentity{Subject: "s"}, trusting(), Context{LinkRequested: true, CurrentUserID: "u"}},
		{ExternalIdentity{Subject: "s", Email: "a@b.c"}, trusting(), Context{LocalUserWithSameEmail: "u"}},
		{ExternalIdentity{Subject: "s"}, Policy{}, Context{}},
	}
	for _, in := range inputs {
		d, _ := Decide(in.ext, in.p, in.c)
		seen[d.Outcome] = true
	}
	for _, o := range []Outcome{SignIn, CreateUser, LinkToCurrentUser, RequireLocalSignIn, Refuse} {
		if !seen[o] {
			t.Errorf("outcome %v is not reachable from any input", o)
		}
	}
}
