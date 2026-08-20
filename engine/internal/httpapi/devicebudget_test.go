package httpapi

import (
	"math"
	"testing"

	"signari.dev/engine/internal/oauth"
)

// RFC 8628 §5.1 does the arithmetic; this pins ours to it.
//
//	"The user code SHOULD have enough entropy that, when combined with
//	rate-limiting and other mitigations, a brute-force attack becomes
//	infeasible... If, for instance, one uses an 8-character base 20 user code
//	(with roughly 34.5 bits of entropy), the rate-limiting interval and validity
//	period would need to only allow 5 attempts in order to get the same 2^-32
//	probability of success by random guessing."
//
// "base 20" is the alphabet size, not a bit count — a distinction this codebase
// previously got wrong in a comment, recording "20 bits" where the RFC means
// 8 characters drawn from 20 symbols. The number that matters is 21^8 for us.
//
// This test exists because all four inputs are constants somebody will one day
// tune for usability — the alphabet, the length, the window, the budget — and
// each looks harmless on its own. The property only exists in their product.
func TestUserCodeGuessingBudgetMeetsRFC8628(t *testing.T) {
	alphabet := float64(len(oauth.DeviceCodeAlphabet))
	space := math.Pow(alphabet, float64(oauth.UserCodeLength))

	// The specification's target, from the 128-bit-key analogy it draws.
	const target = 1.0 / 4294967296.0 // 2^-32

	perUser := float64(deviceAttemptsPerUser) / space
	if perUser > target {
		t.Errorf("a single account may guess %d times per code lifetime, which is "+
			"%.3g against a space of %.0f (%.1f bits) — above §5.1's 2^-32 (%.3g). "+
			"The budget that satisfies it is %d.",
			deviceAttemptsPerUser, perUser, space, math.Log2(space), target,
			int(space*target))
	}

	// The alphabet must not silently shrink: 21^8 is 2^35.14, and the constant
	// carries no meaning if a future edit drops ambiguous letters without
	// re-checking the sum.
	if bits := math.Log2(space); bits < 34.5 {
		t.Errorf("the user code carries %.2f bits; §5.1's worked example uses 34.5 "+
			"and this must not fall below it", bits)
	}
}

// The per-address bucket is deliberately more generous than the per-account one,
// and that ordering is the design rather than an accident.
//
// An address is not scarce — one attacker behind a thousand proxies has a
// thousand address buckets — so it cannot carry the §5.1 property. An account is
// scarce, because the approval page requires a signed-in session and §5.1's
// attack is "approve the authorization grant with their own credentials".
//
// If a later edit tightened the address bucket below the account one, the
// account bucket would stop being reachable and the property would quietly move
// back to the bucket that cannot hold it.
func TestTheAccountBudgetIsTheBindingOne(t *testing.T) {
	if deviceAttemptsPerUser >= deviceAttemptsPerWindow {
		t.Errorf("the per-account budget (%d) is not tighter than the per-address "+
			"one (%d), so the account bucket never binds and §5.1's arithmetic is "+
			"enforced by an address bucket that a proxy pool defeats",
			deviceAttemptsPerUser, deviceAttemptsPerWindow)
	}
}
