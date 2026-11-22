package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// An administrator emails a person a link to register a passkey (4.24). The
// answer names the link, never its token; the email the outbox sends is the
// only place the token exists. A link nobody could receive or use is refused
// rather than reported issued.
func TestAnAdministratorIssuesAPasskeyLink(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID := newDriftUser(t, s)
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.outbox WHERE topic = $1 AND payload->>'user_id' = $2`,
			store.AccountNoticeTopic, userID)
	})

	rec := call(t, s, http.MethodPost, "/admin/users/"+userID+"/passkey-link", testToken,
		map[string]any{"ttl_seconds": 3600})
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") == "" {
		t.Fatalf("issuing: %d %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for k := range got {
		if strings.Contains(k, "token") || strings.Contains(k, "url") {
			t.Errorf("the answer carries %q: the token belongs in the person's email alone", k)
		}
	}
	linkID, _ := got["link_id"].(string)
	expires, err := time.Parse(time.RFC3339, got["expires_at"].(string))
	if err != nil || linkID == "" {
		t.Fatalf("no link named in %s", rec.Body.String())
	}
	if d := time.Until(expires); d < 55*time.Minute || d > 61*time.Minute {
		t.Errorf("an hour's link ends in %s", d)
	}

	// Queued for the outbox by id, with no token minted yet.
	var hashed bool
	var queued int
	if err := s.db.QueryRow(ctx, `
		SELECT token_hash IS NOT NULL,
		       (SELECT count(*) FROM core.outbox WHERE topic = $2 AND payload->>'link_id' = $1)
		  FROM core.passkey_links WHERE id = $1::uuid`, linkID, store.AccountNoticeTopic).
		Scan(&hashed, &queued); err != nil {
		t.Fatal(err)
	}
	if hashed || queued != 1 {
		t.Errorf("token minted before sending: %v; notices queued: %d", hashed, queued)
	}

	for _, c := range []struct {
		name  string
		setup string
		body  map[string]any
		want  int
	}{
		{"a ttl past seven days", "", map[string]any{"ttl_seconds": 8 * 24 * 3600}, http.StatusBadRequest},
		{"a ttl under a minute", "", map[string]any{"ttl_seconds": 5}, http.StatusBadRequest},
		{"no address", `UPDATE core.users SET username = 'nomail-' || id::text, email = NULL
			WHERE id = $1::uuid`, nil, http.StatusConflict},
		{"deactivated", `UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, nil, http.StatusConflict},
	} {
		if c.setup != "" {
			if _, err := s.db.Exec(ctx, c.setup, userID); err != nil {
				t.Fatal(err)
			}
		}
		if rec := call(t, s, http.MethodPost, "/admin/users/"+userID+"/passkey-link", testToken,
			c.body); rec.Code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, rec.Code, rec.Body.String(), c.want)
		}
	}
	if rec := call(t, s, http.MethodPost, "/admin/users/00000000-0000-0000-0000-000000000000/passkey-link",
		testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("a link for nobody: %d, want 404", rec.Code)
	}
}
