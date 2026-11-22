package adminapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func randomPassword(t *testing.T) string {
	t.Helper()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// An administrator clears what wrong guesses charged to one person (4.06):
// the password step's delay, the per-account budgets under each name, the
// second-factor budget. The per-address budgets are left.
func TestAnAdministratorUnlocksAPerson(t *testing.T) {
	s, _ := newTestServer(t)
	org := anyOrgID(t, s)
	ctx := context.Background()
	tag := fmt.Sprint(time.Now().UnixNano())
	email, username := "lock"+tag+"@example.test", "lock"+tag
	rec := call(t, s, http.MethodPost, "/admin/users", testToken, map[string]any{
		"email": email, "username": username, "org_id": org, "password": randomPassword(t),
	})
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("creating the user: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("no id in %s", rec.Body.String())
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = s.db.Exec(c, `DELETE FROM core.users WHERE id = $1::uuid`, created.ID)
	})

	// What a run of wrong guesses leaves behind.
	if _, err := s.db.Exec(ctx, `UPDATE core.password_credentials
		SET failed_attempts = 9, throttled_until = now() + interval '10 minutes', last_failure_at = now()
		WHERE user_id = $1::uuid`, created.ID); err != nil {
		t.Fatal(err)
	}
	ip := "signin:fail:ip:unlock-test-" + tag
	keys := []string{"signin:fail:user:" + email, "signin:fail:user:" + username,
		"mfa:fail:user:" + created.ID, ip}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.rate_limits WHERE bucket_key = ANY($1)`, keys)
	})
	for _, key := range keys {
		if _, err := s.db.Exec(ctx, `INSERT INTO core.rate_limits (bucket_key, window_start, count)
			VALUES ($1, now(), 5)`, key); err != nil {
			t.Fatal(err)
		}
	}

	rec = call(t, s, http.MethodDelete, "/admin/users/"+created.ID+"/throttle", testToken, nil)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") == "" {
		t.Fatalf("unlocking gave %d %s", rec.Code, rec.Body.String())
	}
	var failures int
	var until *time.Time
	if err := s.db.QueryRow(ctx, `SELECT failed_attempts, throttled_until FROM core.password_credentials
		WHERE user_id = $1::uuid`, created.ID).Scan(&failures, &until); err != nil {
		t.Fatal(err)
	}
	if failures != 0 || until != nil {
		t.Errorf("after unlocking: %d failures, delayed until %v", failures, until)
	}
	var left []string
	rows, err := s.db.Query(ctx, `SELECT bucket_key FROM core.rate_limits WHERE bucket_key = ANY($1)`, keys)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k string
		_ = rows.Scan(&k)
		left = append(left, k)
	}
	rows.Close()
	if strings.Join(left, ",") != ip {
		t.Errorf("after unlocking these budgets remain: %v; want only the address's, %s", left, ip)
	}

	if rec := call(t, s, http.MethodDelete, "/admin/users/00000000-0000-0000-0000-000000000000/throttle",
		testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("unlocking nobody gave %d, want 404", rec.Code)
	}
}
