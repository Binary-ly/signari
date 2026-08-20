package httpapi

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
)

// ASVS 5.0 V10.4.2, both halves, end to end.
//
//	"Verify that authorization codes are single-use, and that reuse of an
//	 authorization code revokes the tokens that were issued for it."
//
// TestCodeReuseRevokesTheIssuedTokens already covers this, and covers it
// properly -- it replays the code and then reads core.refresh_token_families to
// confirm revoked_at is set. This test is not filling a gap in that one; it
// asserts the same requirement one layer out, through BEHAVIOUR rather than
// through the flag:
//
//   - the refresh token is exercised BEFORE the replay, so a later failure means
//     the replay killed it rather than that it never worked;
//   - the successor issued by rotation is what gets tried afterwards, so the
//     revocation has to reach a descendant the stolen code produced indirectly,
//     not merely the row whose hash is easy to look up;
//   - deadness is measured by the refresh grant being refused, which is what an
//     attacker actually experiences, rather than by a column.
//
// A family flagged revoked that the refresh grant still honours would pass the
// existing test and lose the account.
func TestCodeReuseRevokesTheTokensTheStolenCodeAlreadyProduced(t *testing.T) {
	f := newTokenFixture(t)
	// PKCE verifiers are 43-128 characters (RFC 7636 §4.1); shorter is refused.
	const verifier = "verifier-for-the-reuse-journey-0123456789-abcdefghij"
	code := f.issueCode(t, verifier)

	// 1. The legitimate redemption.
	status, body := f.post(t, f.redeem(code, verifier))
	if status != http.StatusOK {
		t.Fatalf("first redemption: %d %v", status, body)
	}
	refresh, _ := body["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh token to revoke, so the requirement cannot be tested: %v", body)
	}

	// 2. The refresh token is live. Established BEFORE the replay, so that a
	//    later failure means the replay killed it rather than that it never
	//    worked -- otherwise this test would pass against a server that issued
	//    broken refresh tokens.
	rotated := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh},
		"client_id": {f.clientID}}
	status, body = f.post(t, rotated)
	if status != http.StatusOK {
		t.Fatalf("the refresh token did not work before any reuse, so this test "+
			"could not detect revocation: %d %v", status, body)
	}
	next, _ := body["refresh_token"].(string)
	if next == "" {
		t.Fatalf("rotation returned no successor: %v", body)
	}

	// 3. The stolen code, replayed.
	status, body = f.post(t, f.redeem(code, verifier))
	if status == http.StatusOK {
		t.Fatal("an authorization code was redeemed twice")
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("replay error = %v, want invalid_grant", body["error"])
	}

	// 4. The half that was never verified: the lineage is dead. The successor
	//    from step 2 descends from the stolen code, so it must not survive.
	status, body = f.post(t, url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {next}, "client_id": {f.clientID}})
	if status == http.StatusOK {
		t.Fatal("a refresh token descended from a reused authorization code still " +
			"works; V10.4.2 requires reuse to revoke the tokens the code produced, " +
			"and an attacker who replays a stolen code keeps the victim's session")
	}
}

// V10.4.2's first half under concurrency, which is the case single-use exists for.
//
// A sequential "redeem twice" passes even if the implementation reads the row,
// decides it is unspent, and updates it afterwards. A stolen code is racing the
// legitimate client by construction -- both hold it at the same moment -- so the
// property has to hold when the presentations arrive together.
//
// This is what distinguishes ConsumeCode's `UPDATE ... WHERE consumed_at IS NULL
// RETURNING` from a SELECT followed by an UPDATE.
func TestConcurrentRedemptionOfOneAuthorizationCodeYieldsOneTokenSet(t *testing.T) {
	f := newTokenFixture(t)

	const racers = 8
	for round := 0; round < 3; round++ {
		verifier := "verifier-for-the-concurrent-round-0123456789-abcdef"
		code := f.issueCode(t, verifier)

		var wg sync.WaitGroup
		codes := make([]int, racers)
		start := make(chan struct{})
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				codes[i], _ = f.post(t, f.redeem(code, verifier))
			}(i)
		}
		close(start)
		wg.Wait()

		won := 0
		for _, c := range codes {
			if c == http.StatusOK {
				won++
			}
		}
		if won != 1 {
			t.Fatalf("round %d: %d of %d simultaneous redemptions of one authorization "+
				"code received tokens; exactly one may", round, won, racers)
		}
	}
}

func TestConcurrentRefreshRotationYieldsOneWinnerAndKillsTheFamily(t *testing.T) {
	f := newTokenFixture(t)
	const verifier = "verifier-for-the-refresh-race-0123456789-abcdef"
	code := f.issueCode(t, verifier)

	status, body := f.post(t, f.redeem(code, verifier))
	if status != http.StatusOK {
		t.Fatalf("redemption: %d %v", status, body)
	}
	refresh, _ := body["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh token: %v", body)
	}

	const racers = 4
	var wg sync.WaitGroup
	codes := make([]int, racers)
	winner := make([]string, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			var b map[string]any
			codes[i], b = f.post(t, url.Values{"grant_type": {"refresh_token"},
				"refresh_token": {refresh}, "client_id": {f.clientID}})
			winner[i], _ = b["refresh_token"].(string)
		}(i)
	}
	close(start)
	wg.Wait()

	won, successor := 0, ""
	for i, c := range codes {
		if c == http.StatusOK {
			won++
			successor = winner[i]
		}
	}
	if won != 1 {
		t.Fatalf("%d of %d concurrent rotations of one refresh token succeeded; "+
			"exactly one may, or the lineage forks and two clients hold live "+
			"credentials for one grant", won, racers)
	}

	// The recorded consequence: the winner's successor is already dead, because
	// the losers looked like replay. If this assertion ever fails, someone has
	// introduced a grace window -- which may well be right, but must be a
	// decision rather than an accident.
	status, _ = f.post(t, url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {successor}, "client_id": {f.clientID}})
	if status == http.StatusOK {
		t.Fatal("the successor from a self-race still works, so the family was NOT " +
			"revoked. That is a behaviour change: reuse no longer implies theft. " +
			"If it was intended, update this test and docs/security-review-asvs.md " +
			"V10.4.5 together")
	}
}
