package tokens

import (
	"strings"
	"testing"
)

// HasScope must split scope strings the same way the code that GRANTED them does.
//
// This server had five separate implementations of "does this scope string
// contain this scope", and they did not agree:
//
//	oauth.Authorize          strings.Fields   -- decides what is granted
//	policy.hasScope          strings.Fields
//	oauth.containsScopeValue strings.Fields
//	tokens.HasScope          hand-rolled scan for ' '   <- the odd one out
//	adminapi.Principal.Can   []string, plus a wildcard
//
// The odd one out gated /userinfo. So for a scope string containing a tab,
// authorize granted two scopes and userinfo recognised neither: the grant said
// yes and the consumer said no about the same bytes.
//
// Nothing exploitable followed, because every persistence site routes through
// joinScopes and re-joins with a single space -- the divergence was unreachable
// by accident rather than by construction. This test makes the agreement a
// property of the code instead of a property of who happened to call joinScopes.
func TestHasScopeSplitsLikeTheGrantingCode(t *testing.T) {
	// Every string here is one the two splitters used to disagree about, plus
	// the ordinary cases that must not regress.
	for _, scope := range []string{
		"openid",
		"openid profile email",
		"openid\tadmin",     // tab: Fields sees two, the old scan saw one
		"openid\nadmin",     // newline: same
		"openid  profile",   // doubled space
		" openid ",          // leading and trailing
		"openid\r\nprofile", // CRLF, as a header-injection shaped input
		"",                  // no scope at all
		"   ",               // whitespace only
		"openid-extra",      // must NOT satisfy a request for "openid"
	} {
		fields := strings.Fields(scope)
		// Agreement in the positive direction: every token the granting code
		// would see must be one HasScope recognises.
		for _, want := range fields {
			if !HasScope(scope, want) {
				t.Errorf("HasScope(%q, %q) = false; strings.Fields sees that token, "+
					"so the code that granted the scope and the code consuming it "+
					"disagree about the same string", scope, want)
			}
		}
		// And in the negative: HasScope must not invent a token Fields does not see.
		for _, never := range []string{"openid", "admin", "profile", "email"} {
			inFields := false
			for _, f := range fields {
				if f == never {
					inFields = true
					break
				}
			}
			if got := HasScope(scope, never); got != inFields {
				t.Errorf("HasScope(%q, %q) = %v, but strings.Fields says %v",
					scope, never, got, inFields)
			}
		}
	}
}

// The empty scope is not a scope.
//
// The old scanner returned TRUE for HasScope("a  b", "") -- the empty span
// between two spaces compared equal to the empty want. A caller that failed to
// parse a scope and passed "" would have been told yes.
func TestHasScopeRefusesTheEmptyScope(t *testing.T) {
	for _, scope := range []string{"", "a  b", "openid", " ", "openid profile"} {
		if HasScope(scope, "") {
			t.Errorf("HasScope(%q, \"\") = true; the empty string is not a scope "+
				"and a caller asking about one has already lost track of what it holds",
				scope)
		}
	}
}

// A scope must match whole, never as a prefix.
//
// "openid-extra" satisfying a check for "openid" is the classic shape of this
// bug: a client registers a harmless-looking scope whose name begins with a
// privileged one and is admitted by the privileged check.
func TestHasScopeDoesNotMatchPrefixes(t *testing.T) {
	for _, scope := range []string{"openid-extra", "openidextra", "openid:read", "xopenid"} {
		if HasScope(scope, "openid") {
			t.Errorf("HasScope(%q, \"openid\") = true; a scope must match whole", scope)
		}
	}
	// The inverse: a longer granted scope list still matches its own members.
	if !HasScope("openid-extra openid", "openid") {
		t.Error("a genuine openid token alongside a lookalike must still match")
	}
}
