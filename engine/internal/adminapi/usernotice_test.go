package adminapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// An administrator setting a password or changing an address is told to the
// holder (5.04): queued in the change's transaction, the address change for the
// old address as well, and nothing for a change that is not one.
func TestAnAdministratorsChangeIsToldToTheHolder(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID := newDriftUser(t, s)
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.outbox WHERE topic = $1 AND payload->>'user_id' = $2`,
			store.AccountNoticeTopic, userID)
	})
	var old string
	if err := s.db.QueryRow(ctx, `SELECT email FROM core.users WHERE id = $1::uuid`, userID).Scan(&old); err != nil {
		t.Fatal(err)
	}
	queued := func(notice string) (n int, oldAddress string) {
		t.Helper()
		if err := s.db.QueryRow(ctx, `SELECT count(*), COALESCE(max(payload->>'old_address'), '')
			FROM core.outbox WHERE topic = $1 AND payload->>'user_id' = $2 AND payload->>'notice' = $3`,
			store.AccountNoticeTopic, userID, notice).Scan(&n, &oldAddress); err != nil {
			t.Fatal(err)
		}
		return n, oldAddress
	}

	if rec := call(t, s, http.MethodPatch, "/admin/users/"+userID, testToken,
		map[string]any{"password": randomPassword(t)}); rec.Code != http.StatusOK {
		t.Fatalf("setting the password: %d %s", rec.Code, rec.Body.String())
	}
	if n, _ := queued(store.NoticePasswordSet); n != 1 {
		t.Errorf("%d password-set notices, want 1", n)
	}

	// The same address in other letters is no change.
	if rec := call(t, s, http.MethodPatch, "/admin/users/"+userID, testToken,
		map[string]any{"email": strings.ToUpper(old)}); rec.Code != http.StatusOK {
		t.Fatalf("re-casing the address: %d %s", rec.Code, rec.Body.String())
	}
	if n, _ := queued(store.NoticeEmailChanged); n != 0 {
		t.Errorf("%d address-changed notices for the same address", n)
	}

	if rec := call(t, s, http.MethodPatch, "/admin/users/"+userID, testToken,
		map[string]any{"email": "moved-" + old}); rec.Code != http.StatusOK {
		t.Fatalf("changing the address: %d %s", rec.Code, rec.Body.String())
	}
	if n, to := queued(store.NoticeEmailChanged); n != 1 || !strings.EqualFold(to, old) {
		t.Errorf("address change: %d notices, old address %q; want 1 to %q", n, to, old)
	}
}
