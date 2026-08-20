package httpapi

import (
	"testing"
	"time"

	"signari.dev/engine/internal/clientauth"
)

// Constants that a specification fixes, pinned so a change is a decision.
//
// These are not testing behaviour — the behaviour has its own tests. They are
// testing that a NUMBER has not drifted, because each of these numbers is load
// bearing for a conformance claim made in docs/, and changing one is a one-token
// edit that no behavioural test would notice. `codeTTL = 10 * time.Minute` is
// still a perfectly working authorization server; it is just no longer the one
// the FAPI review says it is.
func TestTheConstantsAConformanceClaimRestsOnHaveNotDrifted(t *testing.T) {
	// FAPI 2.0 Security Profile (Final, 22 Feb 2025) §5.3.2.1: "shall issue
	// authorization codes with a maximum lifetime of 60 seconds".
	//
	// ASVS 5.0 V10.4.3 wants <= 10 minutes at L1/L2 and <= 1 minute at L3, so
	// this same number is what puts us at the L3 bar rather than the L1 one.
	if codeTTL != 60*time.Second {
		t.Errorf("codeTTL = %v, want 60s. FAPI 2.0 §5.3.2.1 sets a maximum "+
			"lifetime of 60 seconds and ASVS 5.0 V10.4.3 L3 wants <= 1 minute; "+
			"docs/security-review-fapi2.md claims \"yes, exactly 60\" and "+
			"docs/security-review-asvs.md claims the L3 bar. Changing this "+
			"invalidates both, so change them together or change it back", codeTTL)
	}

	// §5.3.2.1: "shall accept JWTs with `iat` or `nbf` timestamp between 0 and
	// 10 seconds in the future but shall reject greater than 60 seconds".
	//
	// The band between 10 and 60 is left to the implementation -- "reject
	// greater than 60" does not oblige anyone to accept 59 -- so 10 is the
	// tightest conformant value, and every second above it is a second an
	// assertion is usable before its own client says it should be.
	if clientauth.MaxClockSkew != 10*time.Second {
		t.Errorf("MaxClockSkew = %v, want 10s: the tightest value FAPI 2.0 "+
			"§5.3.2.1 permits. Above 60s it would be non-conformant outright",
			clientauth.MaxClockSkew)
	}
	if clientauth.MaxClockSkew > 60*time.Second {
		t.Error("MaxClockSkew exceeds 60s, which FAPI 2.0 §5.3.2.1 rejects outright")
	}
}
