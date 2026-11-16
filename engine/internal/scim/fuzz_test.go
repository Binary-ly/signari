package scim

import "testing"

// A list filter and a PATCH path are a SCIM client's query text, parsed for every list
// and every change. Each ends in a parse or an error.
func FuzzParseListFilter(f *testing.F) {
	for _, s := range []string{`userName eq "ada"`, `emails[type eq "work"].value co "@"`,
		`name.familyName sw "L" and active eq true`, `not (userName pr)`, `((((`, `"`, ``} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseListFilter(s)
	})
}

func FuzzParsePath(f *testing.F) {
	for _, s := range []string{`emails[type eq "work"].value`, `members`, `name.givenName`,
		`urn:ietf:params:scim:schemas:core:2.0:User:userName`, `[`, `a[b eq "c"`, ``} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParsePath(s)
	})
}
