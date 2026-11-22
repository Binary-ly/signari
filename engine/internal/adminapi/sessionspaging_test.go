package adminapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// A person's sessions are listed page by page, every one once, rather than the
// first 200 and nothing after (6.08).
func TestEverySessionIsListedOncePageByPage(t *testing.T) {
	s, _ := newTestServer(t)
	user := newDriftUser(t, s)
	want := map[string]bool{}
	for i := 0; i < 5; i++ {
		want[newDriftSession(t, s, user)] = true
	}

	seen := map[string]int{}
	var order []string
	cursor := ""
	for pages := 0; pages < 10; pages++ {
		path := "/admin/users/" + user + "/sessions?limit=2"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		rec := call(t, s, http.MethodGet, path, testToken, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("page %d: %d %s", pages, rec.Code, rec.Body.String())
		}
		var page struct {
			Sessions   []sessionSummary `json:"sessions"`
			NextCursor string           `json:"next_cursor"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &page)
		if len(page.Sessions) > 2 {
			t.Fatalf("a page of 2 held %d", len(page.Sessions))
		}
		for _, ss := range page.Sessions {
			seen[ss.SID]++
			order = append(order, ss.CreatedAt+" "+ss.SID)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	for sid := range want {
		if seen[sid] != 1 {
			t.Errorf("session %s listed %d times", sid, seen[sid])
		}
	}
	for i := 1; i < len(order); i++ {
		if order[i] > order[i-1] {
			t.Errorf("not newest first: %q after %q", order[i], order[i-1])
		}
	}
	if rec := call(t, s, http.MethodGet, "/admin/users/"+user+"/sessions?cursor=not-a-cursor", testToken, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("a made-up cursor answered %d", rec.Code)
	}
}
