package httpapi

import (
	"testing"
	"time"
)

// FAPI 2.0 Security Profile §5.3.2.2, requirements for authorization servers.
//
// Two lifetime ceilings, both currently met by constants whose comments cite the
// laxer general-purpose rules rather than the profile:
//
//	"shall issue authorization codes with a maximum lifetime of 60 seconds"
//	"shall issue pushed authorization requests request_uri with expires_in
//	 values of less than 600 seconds"
//
// `codeTTL` is 60s and its comment reads "RFC 6749 recommends <= 10 minutes;
// short is free here" — which is true of RFC 6749 and would be a silent FAPI
// conformance break the moment somebody took the RFC at its word and raised it.
// The constant carries no reference to the profile, so nothing connects the two.
//
// A note on scope, because it matters for how this test should be read: FAPI is
// a profile a deployment opts into, and most of §5.3.2's requirements are
// restrictions (confidential clients only, PAR mandatory, sender-constrained
// tokens only) that a general-purpose IdP correctly does not apply by default.
// These two are different — they are ceilings we already sit under, and holding
// them costs nothing. This test exists so that stops being an accident.
func TestFAPILifetimeCeilingsHold(t *testing.T) {
	// §5.3.2.2: authorization codes, maximum 60 seconds.
	if codeTTL > 60*time.Second {
		t.Errorf("codeTTL is %s; FAPI 2.0 §5.3.2.2 requires authorization codes "+
			"with \"a maximum lifetime of 60 seconds\". RFC 6749's 10-minute "+
			"recommendation is the laxer rule and does not license exceeding this",
			codeTTL)
	}

	// §5.3.2.2: pushed authorization request lifetimes, strictly under 600s.
	if parLifetime >= 600*time.Second {
		t.Errorf("parLifetime is %s; FAPI 2.0 §5.3.2.2 requires request_uri "+
			"expires_in \"of less than 600 seconds\"", parLifetime)
	}
}
