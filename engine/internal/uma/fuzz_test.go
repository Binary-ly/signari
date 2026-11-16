package uma

import "testing"

// A resource server registers resources and asks for permission tickets with JSON
// bodies, and a client names scopes and pushes claim tokens. Each parse ends in a value
// or an error.
func FuzzParseResourceDescription(f *testing.F) {
	for _, s := range []string{`{"resource_scopes":["read"],"name":"photo","type":"https://rs.example/photo"}`,
		`{"resource_scopes":[{"name":"x"}]}`, `{}`, `[]`, `{"resource_scopes":"read"}`, ``} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = ParseResourceDescription(body)
		_, _ = ParsePermissions(body)
	})
}

func FuzzParseScope(f *testing.F) {
	for _, s := range []string{"photo:123:read", "a::b", ":::", "", "eyJ0eXAiOiJKV1QifQ"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _, _, _ = ParseScope(s)
		_, _ = DecodeClaimToken(s)
	})
}
