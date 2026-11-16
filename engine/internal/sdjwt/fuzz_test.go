package sdjwt

import "testing"

// A disclosure is base64url JSON a wallet sends with every presentation. Parsing ends in
// a disclosure or an error.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFkYSJd", "WyJzYWx0IiwiQWRhIl0",
		"WyJzIiwibmFtZSJd", "e30", "", "!!", "W10"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = Parse(s)
	})
}
