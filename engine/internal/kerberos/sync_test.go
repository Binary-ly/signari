package kerberos

import (
	"strings"
	"testing"
)

// kadmin's output carries more than people, and every one of the things
// filtered out below would become an account somebody has to explain.
func TestParsePrincipalsKeepsOnlyPeople(t *testing.T) {
	out := `Authenticating as principal signari/admin@EXAMPLE.COM with keytab.
alice@EXAMPLE.COM
bob@EXAMPLE.COM
host/web01.example.com@EXAMPLE.COM
HTTP/auth.example.com@EXAMPLE.COM
alice/admin@EXAMPLE.COM
kadmin/admin@EXAMPLE.COM
krbtgt/EXAMPLE.COM@EXAMPLE.COM
carol@PARTNER.EXAMPLE
alice@EXAMPLE.COM
`
	got := ParsePrincipals(out, "EXAMPLE.COM")
	want := []string{"alice", "bob"}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParsePrincipalsIsCaseInsensitiveOnRealm(t *testing.T) {
	if got := ParsePrincipals("alice@example.com\n", "EXAMPLE.COM"); len(got) != 1 {
		t.Errorf("a lower-case realm should still match: %v", got)
	}
}

// A missing kadmin and an empty realm produce the same empty list otherwise,
// and only one of them is something an operator can fix.
func TestMissingKadminIsReportedNotSilent(t *testing.T) {
	a := Admin{Realm: "EXAMPLE.COM", Principal: "p", KeytabPath: "k",
		Binary: "kadmin-that-does-not-exist"}
	err := a.Available()
	if err == nil {
		t.Fatal("a missing kadmin was not reported")
	}
	// The error should point at the better route rather than only complaining.
	if !strings.Contains(err.Error(), "LDAP") {
		t.Errorf("the error should mention the LDAP alternative: %v", err)
	}
}

func TestMissingArgumentsAreNamed(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    Admin
	}{
		{"realm", Admin{Principal: "p", KeytabPath: "k"}},
		{"principal", Admin{Realm: "R", KeytabPath: "k"}},
		{"keytab", Admin{Realm: "R", Principal: "p"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.a.Principals(t.Context()); err == nil {
				t.Error("accepted")
			}
		})
	}
}
