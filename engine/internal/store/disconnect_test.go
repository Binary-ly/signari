package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ASVS 5.0 V10.7.3: a user can review, modify and revoke granted consents.
//
// The doc records this as "the connected-applications screen, which revokes the
// tokens with the consent". That second clause is the whole requirement — a
// "revoke access" button that leaves the application working until its refresh
// token expires is not revocation, it is a message — and nothing tested it.
// Neither `DisconnectApp` nor `handleConnectedRevoke` had a single test
// reference.
//
// The risk is specific to how the code is arranged. `WithdrawConsent` on its own
// deliberately does NOT touch tokens, and says so; only `DisconnectApp` does
// both. So the requirement is met by one caller choosing the right function, and
// a future handler that reaches for the obvious-sounding `WithdrawConsent`
// instead would satisfy the screen and lose the property, silently.
func TestDisconnectingAnAppWithdrawsConsentAndKillsItsTokens(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	// fixture() creates a real client row; consents carries a foreign key to it,
	// so an invented client id cannot be used here.
	orgID, userID, clientID, _ := fixture(t, conn)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	if err := RecordConsent(ctx, tx, userID, clientID, []string{"openid", "profile"}); err != nil {
		t.Fatalf("recording consent: %v", err)
	}

	// A session for the family to name, since a family without one is refused.
	sid := "disconnect-sid-" + itoa(time.Now().UnixNano())
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		VALUES ($1, $2, $3::uuid, $4::uuid, 'urn:mace:incommon:iap:silver',
		        ARRAY['pwd'], now(), now() + interval '1 hour')`,
		sid, []byte(sid), orgID, userID); err != nil {
		t.Fatalf("session: %v", err)
	}

	familyID, ferr := NewRefreshFamily(ctx, tx, orgID, clientID, userID, sid, nil, "", "")
	if ferr != nil {
		t.Fatalf("refresh family: %v", ferr)
	}
	raw := "refresh-" + sid
	if err := IssueRefreshToken(ctx, tx, familyID, HashToken(raw),
		[]string{"openid"}, nil, time.Hour); err != nil {
		t.Fatalf("refresh token: %v", err)
	}

	// Prove the lineage is live BEFORE the disconnect, so a later failure means
	// the disconnect caused it rather than that it never worked.
	//
	// Then issue a SUCCESSOR and test that one afterwards. Testing the same
	// token twice would not work: rotation consumes it, so the second attempt
	// fails as reuse whether or not the family was revoked — which is a test
	// that passes for the wrong reason. The first version of this test did
	// exactly that, and a mutation removing `revoked_at = now()` from
	// DisconnectApp survived it.
	if _, err := RotateRefreshToken(ctx, tx, HashToken(raw)); err != nil {
		t.Fatalf("the refresh token did not work before the disconnect, so this "+
			"test could not detect revocation: %v", err)
	}
	successor := "refresh-successor-" + sid
	if err := IssueRefreshToken(ctx, tx, familyID, HashToken(successor),
		[]string{"openid"}, nil, time.Hour); err != nil {
		t.Fatalf("successor token: %v", err)
	}

	revoked, err := DisconnectApp(ctx, tx, userID, clientID)
	if err != nil {
		t.Fatalf("disconnecting: %v", err)
	}
	if revoked == 0 {
		t.Error("DisconnectApp reported revoking no lineages, but one was live")
	}

	// 1. The consent is withdrawn, so the next sign-in asks again rather than
	//    silently re-granting.
	// Read the row directly: CheckConsent takes a pool, and this test lives
	// inside one transaction so that nothing it writes escapes.
	var stillGranted bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM core.consents
		               WHERE user_id = $1::uuid AND client_id = $2
		                 AND withdrawn_at IS NULL)`,
		userID, clientID).Scan(&stillGranted); err != nil {
		t.Fatalf("re-reading consent: %v", err)
	}
	if stillGranted {
		t.Error("consent survived the disconnect; the next authorization request " +
			"would be auto-approved and the app would be back without the user " +
			"being asked")
	}

	// 2. The tokens are dead. This is the half the requirement is actually
	//    about, and the half a consent-only implementation would fail.
	if _, err := RotateRefreshToken(ctx, tx, HashToken(successor)); err == nil {
		t.Error("an unused refresh token in the family still rotates after the " +
			"user revoked access; " +
			"the application keeps working and \"revoke\" was a message, not an act")
	} else if !errors.Is(err, ErrRefreshInvalid) && !errors.Is(err, ErrRefreshReused) {
		t.Errorf("refused, but not as an invalid grant: %v", err)
	}
}
