package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The user list filters (6.08): exact address, a prefix of the address or
// name, and status, each in the query and each served by an index.

func TestTheUserListFilters(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := anyOrgID(t, s)
	stamp := time.Now().UnixNano()
	mk := func(email, username, status string) {
		t.Helper()
		if _, err := s.db.Exec(ctx, `INSERT INTO core.users (org_id, email, username, status, user_handle)
			VALUES ($1::uuid, $2, NULLIF($3, ''), $4, decode(md5(random()::text) || md5(random()::text) ||
			        md5(random()::text) || md5(random()::text), 'hex'))`, org, email, username, status); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE email = $1`, email)
		})
	}
	exact := fmt.Sprintf("Filter.Exact-%d@Example.test", stamp)
	mk(exact, "", "active")
	mk(fmt.Sprintf("filter.other-%d@example.test", stamp), fmt.Sprintf("under_score%d", stamp), "pending")
	mk(fmt.Sprintf("filter.third-%d@example.test", stamp), fmt.Sprintf("underxscore%d", stamp), "deactivated")

	list := func(query string) []string {
		t.Helper()
		rec := call(t, s, http.MethodGet, "/admin/users?limit=50&"+query, testToken, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", query, rec.Code, rec.Body.String())
		}
		var body struct {
			Users []userSummary `json:"users"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		var out []string
		for _, u := range body.Users {
			out = append(out, strings.ToLower(u.Email))
		}
		return out
	}
	if got := list("email=" + url.QueryEscape(strings.ToUpper(exact))); len(got) != 1 || got[0] != strings.ToLower(exact) {
		t.Errorf("an exact address in another case found %v", got)
	}
	if got := list(fmt.Sprintf("q=filter.&status=pending")); len(got) != 1 || !strings.HasPrefix(got[0], "filter.other") {
		t.Errorf("a prefix with a status found %v", got)
	}
	// The underscore in a prefix is a character, not LIKE's any-one wildcard:
	// under_score finds under_score and not underxscore.
	if got := list(fmt.Sprintf("q=under_score%d", stamp)); len(got) != 1 || !strings.HasPrefix(got[0], "filter.other") {
		t.Errorf("an underscore in the prefix matched any character: %v", got)
	}
	if rec := call(t, s, http.MethodGet, "/admin/users?status=gone", testToken, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown status answered %d", rec.Code)
	}
}

// The exact-address lookup is an index scan, as the handler builds it, so a
// deployment-wide token's lookup does not read every person.
func TestAnExactAddressLookupUsesAnIndex(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	if _, err := s.db.Exec(ctx, `ANALYZE core.users`); err != nil {
		t.Fatal(err)
	}
	sql, args := userListQuery("", nil, 51, "somebody@example.test", "", "")
	var plan []byte
	if err := s.db.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+sql, args...).Scan(&plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plan), "users_lower_email_pattern_idx") {
		t.Errorf("the exact-address lookup does not use the address index:\n%s", plan)
	}
}
