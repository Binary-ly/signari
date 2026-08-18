package httpapi

import (
	"os"
	"strings"
	"testing"
)

// Every authentication path writes to the append-only audit trail.
//
// The browser flow, passkeys, Kerberos, MFA and the desktop agent all did.
// **LDAP and RADIUS did not** — two network-facing paths that verify a password
// and answer "yes", leaving nothing behind. An investigation asking how an
// account authenticated on a given day would miss every bind and every
// Access-Accept, and `signari export audit` would show a quiet week for an
// account being used continuously over port 389.
//
// Worse, the doc comment on LDAPAuthenticator asserted the opposite: that a bind
// "is throttled, audited and subject to the same lockout as any other
// authentication". Two of those three were true.
//
// It was found by an unused `userID`: the query fetched the id and nothing
// consumed it, because the write that would have consumed it had never been
// written. That is the whole argument for TestNoParameterIsDiscardedSilently —
// a discarded value is not itself a bug, it is a pointer at one.
func TestTheNetworkAuthenticationPathsAreAudited(t *testing.T) {
	src, err := os.ReadFile("ldapauth.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)

	// Both outcomes, not just the failures. A trail that records only refusals
	// answers "was anyone turned away" and not "who got in", and the second
	// question is the one an investigation starts with.
	for _, want := range []string{
		"audit.EventLoginSucceeded",
		"audit.EventLoginFailed",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the LDAP credential path never writes %s. A bind that "+
				"succeeds must appear in the audit trail, or the trail answers "+
				"the wrong question.", want)
		}
	}

	// The reason a bind failed has to be distinguishable in the trail even
	// though it is deliberately NOT distinguishable to the caller: the LDAP
	// error text is identical for all three, so the audit detail is the only
	// place the difference survives.
	for _, reason := range []string{"unknown_user", "bad_password", "no_identity"} {
		if !strings.Contains(body, reason) {
			t.Errorf("no audit event records the %q failure reason", reason)
		}
	}
}

// RADIUS shares the credential path with LDAP and must not share its label.
//
// `RADIUSAuthenticator` delegates to `LDAPAuthenticator`, so the audit write
// came for free — and would have recorded every Access-Accept as an LDAP bind.
// An investigation would then be told, confidently, that an account
// authenticated over a port it never touched.
func TestRADIUSIsLabelledSeparatelyInTheAuditTrail(t *testing.T) {
	src, err := os.ReadFile("radiusauth.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `withVia("radius")`) {
		t.Fatal("the RADIUS authenticator does not relabel its audit events, so " +
			"every Access-Accept is recorded as an LDAP bind")
	}

	ldapSrc, err := os.ReadFile("ldapauth.go")
	if err != nil {
		t.Fatal(err)
	}
	// The label must come from the field, not be hardcoded — otherwise
	// withVia has no effect and the test above passes while the trail lies.
	if strings.Contains(string(ldapSrc), `"via": "ldap"`) {
		t.Error(`ldapauth.go hardcodes "via": "ldap" in an audit event, so ` +
			"withVia cannot relabel it and RADIUS binds are misattributed")
	}
}
