package adminapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// A rotation over the Admin API replaces what the core compares, the new token is shown
// the once, and the record of it holds the name and not the token. A removal takes the
// row, and a name that is not there is a 404 rather than a success (8.31).
func TestAnOutpostIsRotatedAndRemovedOverTheAdminAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	if _, _, err := store.CreateOutpost(ctx, s.db, org, "dmz", "ldap", ""); err != nil {
		t.Fatal(err)
	}
	send := func(method, path string) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, method, path, "", ""))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}
	path := "/admin/organizations/" + org + "/outposts/dmz"
	rec, out := send(http.MethodPost, path+"/rotate")
	token, _ := out["token"].(string)
	if rec.Code != http.StatusOK || token == "" {
		t.Fatalf("a rotation gave %d %v", rec.Code, out)
	}
	var held []byte
	if err := s.db.QueryRow(ctx, `SELECT token_hash FROM core.outposts WHERE org_id = $1::uuid AND name = 'dmz'`,
		org).Scan(&held); err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256([]byte(token)); !bytes.Equal(held, sum[:]) {
		t.Error("the token shown is not the one the core now compares")
	}
	var detail string
	if err := s.db.QueryRow(ctx, `SELECT detail::text FROM core.audit_events
		WHERE org_id = $1::uuid AND event_type = 'admin.outpost_rotated'`, org).Scan(&detail); err != nil {
		t.Fatalf("the rotation left no record: %v", err)
	}
	if strings.Contains(detail, token) {
		t.Error("the audit record carries the token")
	}

	if rec, out := send(http.MethodDelete, path); rec.Code != http.StatusOK || out["removed"] != true {
		t.Fatalf("a removal gave %d %v", rec.Code, out)
	}
	var left int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM core.outposts WHERE org_id = $1::uuid`, org).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("%d outposts left after the removal", left)
	}
	for _, c := range []struct{ method, path string }{{http.MethodDelete, path}, {http.MethodPost, path + "/rotate"}} {
		if rec, out := send(c.method, c.path); rec.Code != http.StatusNotFound || out["error"] != "outpost_not_found" {
			t.Errorf("%s %s of a removed outpost gave %d %v", c.method, c.path, rec.Code, out)
		}
	}
}
