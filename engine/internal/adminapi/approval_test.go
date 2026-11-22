package adminapi

import (
	"context"
	"net/http"
	"testing"

	"signari.dev/engine/internal/store"
)

// Activating a self-sign-up that waits for approval approves it (5.19): the
// account becomes active, the person is told, and the record says approved.
// Reactivating a deactivated account tells nobody that it was approved.
func TestActivatingAPendingAccountApprovesIt(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	notices := func(userID string) int {
		t.Helper()
		var n int
		if err := s.db.QueryRow(ctx, `SELECT count(*) FROM core.outbox WHERE topic = $1
			AND payload->>'user_id' = $2 AND payload->>'notice' = $3`,
			store.AccountNoticeTopic, userID, store.NoticeAccountApproved).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, c := range []struct {
		from     string
		approved bool
	}{{"pending", true}, {"deactivated", false}} {
		userID := newDriftUser(t, s)
		t.Cleanup(func() {
			_, _ = s.db.Exec(context.Background(), `DELETE FROM core.outbox WHERE topic = $1 AND payload->>'user_id' = $2`,
				store.AccountNoticeTopic, userID)
		})
		if _, err := s.db.Exec(ctx, `UPDATE core.users SET status = $2 WHERE id = $1::uuid`, userID, c.from); err != nil {
			t.Fatal(err)
		}
		if rec := call(t, s, http.MethodPatch, "/admin/users/"+userID, testToken, map[string]any{"active": true}); rec.Code != http.StatusOK {
			t.Fatalf("activating a %s account gave %d %s", c.from, rec.Code, rec.Body.String())
		}
		var status string
		var recorded bool
		if err := s.db.QueryRow(ctx, `SELECT u.status, coalesce((SELECT (detail->>'approved')::bool FROM core.audit_events
			WHERE subject_id = u.id AND event_type = 'admin.user_updated' ORDER BY id DESC LIMIT 1), false)
			FROM core.users u WHERE u.id = $1::uuid`, userID).Scan(&status, &recorded); err != nil {
			t.Fatal(err)
		}
		told := notices(userID) == 1
		if status != "active" || told != c.approved || recorded != c.approved {
			t.Errorf("activating a %s account: status %s, told %v, recorded approved %v; want active, %v, %v",
				c.from, status, told, recorded, c.approved, c.approved)
		}
	}
}
