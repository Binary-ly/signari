package config

import (
	"strings"
	"testing"
)

func TestConfigRefusesTheRedirectURIsTheSharedValidatorRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		uri  string
		want string // a fragment of the expected complaint
	}{
		"response parameter in the fragment": {
			// The fragment response mode APPENDS to whatever is registered, so
			// delivery yields `code=attacker&code=<real>` and a relying party
			// reading the first occurrence reads the attacker's.
			"https://rp.example/cb#code=attacker", "code",
		},
		"response parameter in the query": {
			"https://rp.example/cb?state=attacker", "state",
		},
		"user information before the host": {
			// Reads as rp.example, resolves to evil.example. Accepted by a
			// `strings.HasPrefix(u, "https://")` test.
			"https://rp.example@evil.example/cb", "user information",
		},
		"loopback by prefix only": {
			// Accepted by `strings.HasPrefix(u, "http://localhost")`.
			"http://localhost.evil.com/cb", "loopback",
		},
		"a scheme that is not a redirect scheme": {
			"javascript:alert(1)", "scheme",
		},
		"wildcard": {
			"https://*.rp.example/cb", "wildcard",
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := File{Clients: []Client{{
				ClientID: "c", RedirectURIs: []string{tc.uri},
				Scopes: []string{"openid"},
			}}}
			err := f.Validate()
			if err == nil {
				t.Fatalf("the configuration accepted %q", tc.uri)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Errorf("refused %q but not for the expected reason:\n%v", tc.uri, err)
			}
		})
	}
}

// And an ordinary client must still apply, or the check above is just an outage.
func TestConfigStillAcceptsOrdinaryRedirectURIs(t *testing.T) {
	for _, uri := range []string{
		"https://rp.example/callback",
		"https://rp.example/cb?tenant=acme", // a non-response query parameter is fine
		"http://localhost:8080/cb",
		"http://127.0.0.1:9000/cb",
		"com.example.app:/oauth2redirect", // RFC 8252 private-use scheme
	} {
		f := File{Clients: []Client{{
			ClientID: "c", RedirectURIs: []string{uri}, Scopes: []string{"openid"},
		}}}
		if err := f.Validate(); err != nil {
			t.Errorf("refused a legitimate redirect URI %q: %v", uri, err)
		}
	}
}

func TestSecureURLIsParsedNotPrefixMatched(t *testing.T) {
	for uri, want := range map[string]bool{
		"https://example.test/x":          true,
		"http://localhost:3000/x":         true,
		"http://127.0.0.1/x":              true,
		"http://localhost.evil.com/x":     false,
		"https://good.example@evil.test/": false,
		"http://example.test/x":           false,
		"javascript:alert(1)":             false,
		"/relative":                       false,
	} {
		if got := secureURL(uri); got != want {
			t.Errorf("secureURL(%q) = %v, want %v", uri, got, want)
		}
	}
}
