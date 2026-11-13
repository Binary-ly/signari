package federation

import "testing"

// Every decision a sign-in page shows carries the message key the page says it with
// in the reader's language. The page used to show Reason, in English, to everybody.
func TestEveryRefusalCarriesAMessageKey(t *testing.T) {
	ext := ExternalIdentity{Subject: "sub-1", Email: "ada@example.test"}
	for name, c := range map[string]struct {
		p   Policy
		ctx Context
	}{
		"linking not allowed":          {Policy{}, Context{LinkRequested: true, CurrentUserID: "u1"}},
		"an address taken, no linking": {Policy{AllowSignup: true}, Context{LocalUserWithSameEmail: "u2"}},
		"an address taken":             {Policy{AllowSignup: true, AllowLinking: true}, Context{LocalUserWithSameEmail: "u2"}},
		"sign-up closed":               {Policy{}, Context{}},
		"an address not confirmed":     {Policy{AllowSignup: true, RequireVerifiedEmail: true}, Context{}},
	} {
		d, err := Decide(ext, c.p, c.ctx)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d.Outcome != Refuse && d.Outcome != RequireLocalSignIn {
			t.Fatalf("%s: outcome %s, the case is not a refusal", name, d.Outcome)
		}
		if d.Key == "" || d.Reason == "" {
			t.Errorf("%s: key %q, reason %q", name, d.Key, d.Reason)
		}
	}
}
