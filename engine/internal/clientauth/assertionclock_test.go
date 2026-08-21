package clientauth

import (
	"strings"
	"testing"
	"time"
)

// TestModestClockSkewOnNotBeforeIsTolerated is the "shall accept" half.
func TestModestClockSkewOnNotBeforeIsTolerated(t *testing.T) {
	k := newKey(t, "k1")
	now := time.Now()

	for _, skew := range []time.Duration{time.Second, 5 * time.Second, 10 * time.Second} {
		c := goodClaims()
		c["nbf"] = now.Add(skew).Unix()
		if _, err := VerifyPrivateKeyJWT(k.sign(t, c), testClientID, k.jwks(t),
			testAudiences, now); err != nil {
			t.Errorf("nbf %s in the future was refused: %v\nFAPI 2.0 5.3.2.1 requires "+
				"accepting 0 to 10 seconds; a client whose clock runs slightly fast "+
				"cannot authenticate at all", skew, err)
		}
	}
}

// TestModestClockSkewOnIssuedAtIsTolerated -- same requirement, other claim.
func TestModestClockSkewOnIssuedAtIsTolerated(t *testing.T) {
	k := newKey(t, "k1")
	now := time.Now()

	for _, skew := range []time.Duration{time.Second, 10 * time.Second} {
		c := goodClaims()
		c["iat"] = now.Add(skew).Unix()
		if _, err := VerifyPrivateKeyJWT(k.sign(t, c), testClientID, k.jwks(t),
			testAudiences, now); err != nil {
			t.Errorf("iat %s in the future was refused: %v", skew, err)
		}
	}
}

// TestAnAssertionIssuedFarInTheFutureIsRefused is the "shall reject" half.
//
// The security question underneath: an assertion dated forward is one whose
// usable window has been moved rather than extended, and combined with a
// replay cache that expires by `exp` it is a credential that outlives what the
// server thinks it agreed to.
func TestAnAssertionIssuedFarInTheFutureIsRefused(t *testing.T) {
	k := newKey(t, "k1")
	now := time.Now()

	for _, skew := range []time.Duration{61 * time.Second, 2 * time.Minute} {
		c := goodClaims()
		c["iat"] = now.Add(skew).Unix()
		// exp kept inside MaxAssertionLifetime, so the ONLY thing that can refuse
		// this is an iat check. Without that, the lifetime bound accepts it.
		c["exp"] = now.Add(skew + 30*time.Second).Unix()

		_, err := VerifyPrivateKeyJWT(k.sign(t, c), testClientID, k.jwks(t),
			testAudiences, now)
		if err == nil {
			t.Errorf("an assertion issued %s in the future was accepted; FAPI 2.0 "+
				"5.3.2.1 requires rejecting more than 60 seconds", skew)
			continue
		}
		if !strings.Contains(err.Error(), "future") {
			t.Errorf("iat %s in the future was refused, but for another reason (%v) -- "+
				"so the iat check is still absent and something else happened to "+
				"catch it", skew, err)
		}
	}
}

// TestANotBeforeFarInTheFutureIsRefused -- the same bound on the other claim.
func TestANotBeforeFarInTheFutureIsRefused(t *testing.T) {
	k := newKey(t, "k1")
	now := time.Now()

	c := goodClaims()
	c["nbf"] = now.Add(2 * time.Minute).Unix()
	c["exp"] = now.Add(4 * time.Minute).Unix()
	if _, err := VerifyPrivateKeyJWT(k.sign(t, c), testClientID, k.jwks(t),
		testAudiences, now); err == nil {
		t.Error("an assertion not valid for another two minutes was accepted")
	}
}

// TestAnAssertionIssuedLongAgoIsRefused.
//
// MaxAssertionLifetime exists so an assertion cannot be a long-lived bearer
// credential -- the very thing private_key_jwt replaces. It measures `exp`
// against now, and therefore only bounds the window FORWARDS: an assertion
// minted an hour ago with `exp` two minutes out satisfies it completely, having
// been usable for that entire hour.
//
// This test exists because the check that closes that gap survived a mutation.
// Removing the bound broke no test, which means the bound was not yet known to
// be doing anything -- and an unexercised branch in credential validation is
// indistinguishable from a comment.
func TestAnAssertionIssuedLongAgoIsRefused(t *testing.T) {
	k := newKey(t, "k1")
	now := time.Now()

	c := goodClaims()
	c["iat"] = now.Add(-time.Hour).Unix()
	// Deliberately inside MaxAssertionLifetime measured from now, so the forward
	// bound cannot be what refuses this. If the iat bound is absent, it passes.
	c["exp"] = now.Add(2 * time.Minute).Unix()

	_, err := VerifyPrivateKeyJWT(k.sign(t, c), testClientID, k.jwks(t), testAudiences, now)
	if err == nil {
		t.Fatal("an assertion minted an hour ago was accepted; it was a usable " +
			"credential for that hour, which is what MaxAssertionLifetime exists to " +
			"prevent and does not measure")
	}
	if !strings.Contains(err.Error(), "ago") {
		t.Errorf("refused, but not as a stale assertion (%v) -- so something else "+
			"caught it and the bound is still unexercised", err)
	}
}

// TestAnAssertionWithNoIssuedAtStillWorks.
//
// RFC 7523 §3 makes `iat` OPTIONAL. Every check added above is conditional on it
// being present, and this pins that: making a claim the RFC calls optional into
// a requirement would break clients that are entirely correct.
func TestAnAssertionWithNoIssuedAtStillWorks(t *testing.T) {
	k := newKey(t, "k1")
	now := time.Now()

	c := goodClaims()
	delete(c, "iat")
	if _, err := VerifyPrivateKeyJWT(k.sign(t, c), testClientID, k.jwks(t),
		testAudiences, now); err != nil {
		t.Errorf("an assertion without iat was refused: %v -- RFC 7523 makes it optional", err)
	}
}
