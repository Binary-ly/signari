package httpapi

import (
	"context"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// A user sees only their own sessions, and cannot revoke another user's by
// presenting its sid in the form.
//
// TerminateSessions keys on the sid alone, so the ownership check in the handler
// is the only thing standing between a guessed sid and ending a stranger's
// session. This asserts both halves: the list is scoped to the caller, and the
// ownership predicate refuses a foreign sid.
func TestAUserCannotSeeOrRevokeAnotherUsersSession(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	// A second user in the same org, with a live session.
	var otherID string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, status, user_handle, email)
		VALUES ($1::uuid, 'active', decode(repeat('ab',64),'hex'),
		        'other-session-user-'||substr(md5(random()::text),1,8)||'@example.test')
		RETURNING id::text`, f.orgID).Scan(&otherID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, otherID)
	})
	otherSID := "other-user-session-" + otherID
	mySID := "my-own-session-" + f.userID
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.sessions WHERE sid = ANY($1)`, []string{otherSID, mySID})
	})
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.sessions (sid, org_id, user_id, auth_time, not_after)
		VALUES ($1, $2::uuid, $3::uuid, now(), now() + interval '12 hours')`,
		otherSID, f.orgID, otherID); err != nil {
		t.Fatal(err)
	}

	// A session for OUR user too, so the list is not trivially empty.
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.sessions (sid, org_id, user_id, auth_time, not_after)
		VALUES ($1, $2::uuid, $3::uuid, now(), now() + interval '12 hours')`,
		mySID, f.orgID, f.userID); err != nil {
		t.Fatal(err)
	}

	// The list is scoped to the caller.
	sessions, err := store.ListUserSessions(ctx, f.pool, f.userID, mySID)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sessions {
		if s.SID == otherSID {
			t.Fatal("ListUserSessions returned another user's session")
		}
	}
	found := false
	for _, s := range sessions {
		if s.SID == mySID {
			found = true
			if !s.Current {
				t.Error("the caller's own session was not marked current")
			}
		}
	}
	if !found {
		t.Fatal("ListUserSessions did not return the caller's own session")
	}

	// The ownership predicate refuses the foreign sid and accepts the owned one.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if owned, err := userOwnsSession(ctx, tx, f.userID, otherSID); err != nil || owned {
		t.Errorf("userOwnsSession(caller, foreign sid) = %v (err %v); a user must "+
			"not be able to revoke another's session", owned, err)
	}
	if owned, err := userOwnsSession(ctx, tx, f.userID, mySID); err != nil || !owned {
		t.Errorf("userOwnsSession(caller, own sid) = %v (err %v); want true", owned, err)
	}
}

// A revoked or expired session does not appear in the list.
func TestRevokedSessionsAreNotListed(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	deadSID := "already-revoked-" + f.userID
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.sessions WHERE sid = $1`, deadSID)
	})
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.sessions (sid, org_id, user_id, auth_time, not_after, revoked_at, revocation_reason)
		VALUES ($1, $2::uuid, $3::uuid, now(), now() + interval '12 hours', now(), 'user_revoke')`,
		deadSID, f.orgID, f.userID); err != nil {
		t.Fatal(err)
	}
	// The new reason must satisfy the CHECK constraint migration 0106 widened.
	sessions, err := store.ListUserSessions(ctx, f.pool, f.userID, "")
	if err != nil {
		t.Fatalf("listing (also proves the user_revoke reason is accepted): %v", err)
	}
	for _, s := range sessions {
		if s.SID == deadSID {
			t.Error("a revoked session was listed as active")
		}
	}
	_ = time.Now
}
