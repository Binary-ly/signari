package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A provider with no ID token: the access token is taken to its userinfo endpoint and the
// person read from the paths an operator named (8.15). A numeric id survives whole, a nested
// path is followed, an address counts as verified only on a JSON true, and a sign-in with no
// identifier goes no further, since linking people by an empty one gives them one account.
func TestAnOAuth2ProviderSaysWhoSomebodyIsFromItsUserinfo(t *testing.T) {
	var answer string
	var bearer, accept string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, accept = r.Header.Get("Authorization"), r.Header.Get("Accept")
		if answer == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(upstream.Close)

	c := Config{Kind: KindOAuth2, UserinfoOverride: upstream.URL + "/api/user",
		Userinfo: UserinfoClaims{Subject: "user.id", Email: "email", EmailVerified: "contact.confirmed",
			Name: "user.full_name"}}
	fetch := func() (ExternalIdentity, error) {
		t.Helper()
		return c.FetchIdentity(context.Background(), upstream.Client(), &TokenSet{AccessToken: "an-access-token"}, "")
	}

	answer = `{"user":{"id":90071992547409931,"full_name":"Ada"},"email":"ada@example.test",
		"contact":{"confirmed":true},"plan":"gold"}`
	id, err := fetch()
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "Bearer an-access-token" || accept != "application/json" {
		t.Errorf("the provider was asked with %q, %q", bearer, accept)
	}
	if id.Subject != "90071992547409931" {
		t.Errorf("subject %q; an id past 2^53 read through a float comes back as somebody else's", id.Subject)
	}
	if id.Email != "ada@example.test" || id.Name != "Ada" || !id.EmailVerified {
		t.Errorf("identity %+v", id)
	}
	var raw map[string]any
	if err := json.Unmarshal(id.RawClaims, &raw); err != nil || raw["plan"] != "gold" {
		t.Errorf("the answer is kept for attribute mapping: %s, %v", id.RawClaims, err)
	}

	answer = `{"user":{"id":"u-7"},"email":"ada@example.test","contact":{"confirmed":"true"}}`
	if id, err := fetch(); err != nil || id.Subject != "u-7" || id.EmailVerified {
		t.Errorf("a string id, and a confirmation that is not a JSON true: %+v, %v", id, err)
	}

	c.Userinfo.EmailVerified = ""
	answer = `{"user":{"id":7},"email":"ada@example.test","contact":{"confirmed":true},"email_verified":true}`
	if id, err := fetch(); err != nil || id.EmailVerified {
		t.Errorf("with no path named nothing is verified, whatever the answer holds: %+v, %v", id, err)
	}

	for _, c2 := range []struct{ name, body, want string }{
		{"no identifier", `{"email":"ada@example.test"}`, "no identifier"},
		{"an empty one", `{"user":{"id":""}}`, "no identifier"},
		{"a fraction", `{"user":{"id":1.5}}`, "no identifier"},
		{"an object", `{"user":{"id":{"n":1}}}`, "no identifier"},
		{"not an object", `[1,2]`, "did not answer an object"},
		{"a refusal", ``, "answered 401"},
	} {
		answer = c2.body
		if id, err := fetch(); err == nil || !strings.Contains(err.Error(), c2.want) {
			t.Errorf("%s: %+v, %v", c2.name, id, err)
		}
	}

	// It sends no nonce, since there is no ID token for one to be bound into.
	if u := c.AuthorizeURL("https://rp.test/cb", "state", "a-nonce", "a-verifier", nil); strings.Contains(u, "nonce") {
		t.Errorf("the authorization URL asks for a nonce: %s", u)
	}
}
