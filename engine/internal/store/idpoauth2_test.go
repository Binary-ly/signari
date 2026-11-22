package store

import (
	"strings"
	"testing"

	"signari.dev/engine/internal/federation"
)

// An OAuth 2.0 provider has nothing to discover, so what cannot work is refused in front of
// whoever typed it (8.15). Nothing a token says is signed, which makes https the whole of
// the trust, and believing an address needs somewhere for the provider to say so.
func TestAnOAuth2ProviderIsCheckedWhenItIsRegistered(t *testing.T) {
	good := func() IdentityProviderSpec {
		return IdentityProviderSpec{Slug: "forge", Kind: "oauth2", ClientID: "c",
			AuthorizeURL: "https://git.example.test/a", TokenURL: "https://git.example.test/t",
			UserinfoURL: "https://git.example.test/u"}
	}
	s := good()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.Userinfo != (federation.UserinfoClaims{Subject: "sub", Email: "email", Name: "name"}) {
		t.Errorf("the defaults are %+v", s.Userinfo)
	}
	for _, c := range []struct {
		name string
		edit func(*IdentityProviderSpec)
		want string
	}{
		{"no authorization endpoint", func(s *IdentityProviderSpec) { s.AuthorizeURL = "" }, "authorization"},
		{"a plaintext token endpoint", func(s *IdentityProviderSpec) { s.TokenURL = "http://git.example.test/t" }, "token"},
		{"a plaintext userinfo endpoint", func(s *IdentityProviderSpec) { s.UserinfoURL = "http://git.example.test/u" }, "userinfo"},
		{"trust with nowhere to read it", func(s *IdentityProviderSpec) { s.TrustEmailVerification = true }, "path"},
		{"no client", func(s *IdentityProviderSpec) { s.ClientID = "" }, "client id"},
	} {
		s := good()
		c.edit(&s)
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a refusal naming %q", c.name, err, c.want)
		}
	}
	s = good()
	s.TrustEmailVerification = true
	s.Userinfo.EmailVerified = "confirmed"
	if err := s.Validate(); err != nil {
		t.Errorf("trust with a path: %v", err)
	}
	// A named provider's belief stays what the preset says.
	named := IdentityProviderSpec{Slug: "g", Kind: "google", ClientID: "c", TrustEmailVerification: true}
	if err := named.Validate(); err == nil {
		t.Error("a named provider took a setting that is the preset's")
	}
}
