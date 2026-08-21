package clients

import (
	"strings"
	"testing"
)

// RFC 9700 §2.6: an authorization server "SHOULD NOT allow clients to influence
// their `client_id` or any other claim that could cause confusion with a genuine
// resource owner".
//
// The confusion here is concrete rather than theoretical. A user's `sub` in this
// engine is their UUID; the client_credentials grant puts the client's identifier
// in `sub`. A client registered under a UUID therefore obtains tokens whose `sub`
// is byte-identical to that user's, and any resource server that reads `sub` to
// find a user — which is how resource servers are ordinarily written — cannot
// tell them apart.

func TestAUUIDShapedClientIDIsRefused(t *testing.T) {
	for _, id := range []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"550E8400-E29B-41D4-A716-446655440000", // upper case is the same value
		"00000000-0000-0000-0000-000000000000",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
	} {
		err := ValidateClientID(id)
		if err == nil {
			t.Errorf("%q was accepted; a client_credentials token for it would carry "+
				"a `sub` indistinguishable from that user's", id)
			continue
		}
		// The refusal has to explain itself: an operator who picked a UUID had a
		// reason, and "invalid client_id" would read as a formatting rule.
		if !strings.Contains(err.Error(), "sub") {
			t.Errorf("%q was refused without explaining the confusion: %v", id, err)
		}
	}
}

// And ordinary identifiers must still work, including ones that merely contain
// hex and hyphens. A rule that refuses `web-app-01` is a rule that gets removed.
func TestOrdinaryClientIDsAreAccepted(t *testing.T) {
	for _, id := range []string{
		"web-app",
		"web-app-01",
		"bench-cc",
		"dyn_aGVsbG8td29ybGQtdG9rZW4",
		"service.internal.billing",
		"550e8400-e29b-41d4-a716", // too short to be a UUID
		"550e8400e29b41d4a716446655440000",
		"a-550e8400-e29b-41d4-a716-446655440000", // prefixed, so not a bare subject
		"deadbeef-cafe-babe-face-000000000000-x",
	} {
		if err := ValidateClientID(id); err != nil {
			t.Errorf("%q was refused: %v", id, err)
		}
	}
}

func TestAnEmptyClientIDIsRefused(t *testing.T) {
	if err := ValidateClientID(""); err == nil {
		t.Error("an empty client_id was accepted")
	}
}
