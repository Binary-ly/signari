package store

import (
	"context"
	"testing"
)

// ASVS 5.0 V10.4.8: refresh tokens must have an absolute expiration, "including
// if sliding refresh token expiration is applied".
//
// Ours is not a cap on the token; it is a cap on the authorization. Rotation
// mints a new token with a fresh expiry, so the token-level deadline slides.
// What does not slide is `sessions.not_after`: it is fixed when the session is
// created, is updated nowhere in the codebase, and RotateRefreshToken requires
// it to be in the future. So a lineage cannot outlive the sign-in that started
// it, however many times it rotates.
//
// That whole chain hangs on the family naming a session. The rotation query
// reads `s.sid IS NULL OR (s.revoked_at IS NULL AND s.not_after > now())`, so a
// family with no sid is vacuously live forever. No caller creates one today —
// this test is the guard that keeps it that way, because "no caller does that"
// describes the code as it stands, not as it will be.
func TestARefreshFamilyMustNameASession(t *testing.T) {
	tx, orgID, userID := waFixture(t)
	ctx := context.Background()

	if _, err := NewRefreshFamily(ctx, tx, orgID, "any-client", userID, "", nil); err == nil {
		t.Fatal("a refresh family with no session was created; its lineage would " +
			"have no absolute expiration, because the rotation query treats a null " +
			"sid as a live session")
	}
}
