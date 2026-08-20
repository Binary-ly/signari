package oauth

import (
	"strings"
	"testing"
)

// RFC 8693 §4.4's worked example, used as the test matrix.
//
//	"may_act": { "sub": "admin@example.com" }
//
// "The claims of the token itself are about user@example.com while the "may_act"
// claim indicates that admin@example.com is authorized to act on behalf of
// user@example.com."
func TestMayActNamesWhoMayAct(t *testing.T) {
	const iss = "https://issuer.example.com"

	for _, tc := range []struct {
		name      string
		mayAct    map[string]any
		clientID  string
		subject   string
		wantRefus bool
	}{
		{
			name:   "absent: the issuer expressed no opinion",
			mayAct: nil, clientID: "anything", subject: "anyone",
		},
		{
			name:   "empty object behaves as absent",
			mayAct: map[string]any{}, clientID: "anything", subject: "anyone",
		},
		{
			name:    "sub matches the acting party",
			mayAct:  map[string]any{"sub": "admin@example.com"},
			subject: "admin@example.com", clientID: "cli",
		},
		{
			name:    "sub names somebody else",
			mayAct:  map[string]any{"sub": "admin@example.com"},
			subject: "mallory@example.com", clientID: "cli",
			wantRefus: true,
		},
		{
			name:     "client_id matches",
			mayAct:   map[string]any{"client_id": "trusted-gateway"},
			clientID: "trusted-gateway", subject: "anyone",
		},
		{
			name:     "client_id names a different client",
			mayAct:   map[string]any{"client_id": "trusted-gateway"},
			clientID: "some-other-client", subject: "anyone",
			wantRefus: true,
		},
		{
			// §4.4: "the combination of the two claims "iss" and "sub" are
			// sometimes necessary to uniquely identify an authorized actor".
			name:    "iss and sub together, both matching",
			mayAct:  map[string]any{"iss": iss, "sub": "admin@example.com"},
			subject: "admin@example.com", clientID: "cli",
		},
		{
			name:    "iss and sub together, sub matching and iss not",
			mayAct:  map[string]any{"iss": "https://elsewhere.example", "sub": "admin@example.com"},
			subject: "admin@example.com", clientID: "cli",
			wantRefus: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckMayAct(tc.mayAct, tc.clientID, tc.subject, iss)
			if tc.wantRefus && err == nil {
				t.Error("the exchange was permitted despite may_act naming another party")
			}
			if !tc.wantRefus && err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}
}

// A member we cannot evaluate must refuse, not be skipped.
//
// §4.4 fixes no member set — "the "email" claim might be used to provide
// additional useful information about that party" — so an issuer may write
// members this server has never heard of. Checking the ones we recognise and
// ignoring the rest would honour half a restriction while reporting success,
// which is worse than not implementing the claim at all: the operator believes
// the constraint held.
func TestAnUnknownMayActMemberRefuses(t *testing.T) {
	err := CheckMayAct(
		map[string]any{"sub": "admin@example.com", "department": "finance"},
		"cli", "admin@example.com", "https://issuer.example.com")
	if err == nil {
		t.Fatal("may_act carried a member this server cannot evaluate and the " +
			"exchange was permitted; half a restriction is not a restriction")
	}
	if !strings.Contains(err.Error(), "department") {
		t.Errorf("the refusal should name the member it could not evaluate: %v", err)
	}
}

// exp, nbf and aud are explicitly not meaningful inside may_act.
//
// §4.4: "claims such as "exp", "nbf", and "aud" are not meaningful when used
// within a "may_act" claim and are therefore not used." Their presence means
// whatever built the claim misunderstood it, and guessing at intent is how a
// constraint gets silently downgraded.
func TestTimeClaimsInsideMayActAreRefused(t *testing.T) {
	for _, member := range []string{"exp", "nbf", "aud"} {
		err := CheckMayAct(
			map[string]any{"sub": "admin@example.com", member: "whatever"},
			"cli", "admin@example.com", "https://issuer.example.com")
		if err == nil {
			t.Errorf("may_act carrying %q was accepted; §4.4 says it is not "+
				"meaningful there", member)
		}
	}
}

// A non-string member cannot be matched against an identifier.
func TestNonStringMayActMemberRefuses(t *testing.T) {
	if err := CheckMayAct(map[string]any{"sub": 42}, "cli", "admin",
		"https://issuer.example.com"); err == nil {
		t.Error("may_act.sub was a number and the exchange was permitted")
	}
}
