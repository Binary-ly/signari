package rar

import "testing"

// authorization_details is a client's JSON in an authorization or token request
// (RFC 9396). Parsing ends in details or an error, and validating what parsed against
// an empty registry answers rather than panics.
func FuzzParse(f *testing.F) {
	for _, s := range []string{`[{"type":"payment_initiation","actions":["initiate"],"locations":["https://rs.example"]}]`,
		`[{"type":"x","datatypes":["a"],"identifier":"i","privileges":["p"]}]`, `[{}]`, `[]`, `{}`, `[{"type":1}]`, ``} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		details, objs, err := Parse(raw)
		if err != nil {
			return
		}
		_ = Validate(details, objs, nil)
	})
}
