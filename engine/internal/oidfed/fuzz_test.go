package oidfed

import "testing"

// An entity statement is fetched from another entity's well-known address, or posted by
// a client registering explicitly, and parsed before its signature means anything.
// Parsing ends in a statement or an error.
func FuzzParseStatement(f *testing.F) {
	for _, s := range []string{
		"eyJhbGciOiJFUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0In0.eyJpc3MiOiJodHRwczovL2EuZXhhbXBsZSIsInN1YiI6Imh0dHBzOi8vYS5leGFtcGxlIn0.AAAA",
		"a.b.c", "..", "", "eyJ9.e30.x",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseStatement(s)
	})
}
