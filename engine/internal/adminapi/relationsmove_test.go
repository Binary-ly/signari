package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// A grant to an address means the person who held it. Giving the address up gave
// the grant up too: it stayed behind for whoever took the address next, and the
// person lost it. It moves to their id, in whatever case it was written, with its
// expiry, and without colliding with the same grant by id.
func TestARelationFollowsItsHolderToAnotherName(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	tag := time.Now().UnixNano()
	address := fmt.Sprintf("mover%d@example.test", tag)
	username := fmt.Sprintf("mover%d", tag)

	create := func(email, name string) string {
		t.Helper()
		var id string
		if err := s.db.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, email, username)
			VALUES ($1::uuid, sha256(gen_random_uuid()::text::bytea), $2, NULLIF($3, '')) RETURNING id::text`,
			org, email, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, id) })
		return id
	}
	grant := func(subject, relation, object string, extra map[string]any) {
		t.Helper()
		body := map[string]any{"subject": subject, "relation": relation, "object": object}
		for k, v := range extra {
			body[k] = v
		}
		if rec := call(t, s, http.MethodPut, "/admin/organizations/"+org+"/relations", testToken, body); rec.Code != http.StatusOK {
			t.Fatalf("granting to %s: %d %s", subject, rec.Code, rec.Body.String())
		}
	}
	held := func(subject, relation, object string) bool {
		t.Helper()
		got, err := store.HoldsAny(ctx, s.db, org, "user", subject, []string{relation}, "document", object, nil)
		if err != nil {
			t.Fatal(err)
		}
		return got != ""
	}

	person := create(address, username)
	end := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	grant("user:"+address, "viewer", "document:1", nil)
	grant("user:"+strings.ToUpper(address), "editor", "document:1", map[string]any{"expires_at": end})
	grant("user:"+address, "owner", "document:2", nil)
	grant("user:"+person, "owner", "document:2", nil) // the same grant by id, which must not collide
	grant("user:"+username, "viewer", "document:3", nil)
	grant("group:staff", "manager", "user:"+address, nil)
	grant("service:billing", "viewer", "document:1", nil)

	// An edit that keeps both names moves nothing.
	if rec := call(t, s, http.MethodPatch, "/admin/users/"+person, testToken,
		map[string]any{"email": strings.ToUpper(address)}); rec.Code != http.StatusOK {
		t.Fatalf("changing the case: %d %s", rec.Code, rec.Body.String())
	}
	if !held(address, "viewer", "1") {
		t.Fatal("a change of case moved the grant")
	}

	if rec := call(t, s, http.MethodPatch, "/admin/users/"+person, testToken, map[string]any{
		"email": fmt.Sprintf("moved%d@example.test", tag), "username": fmt.Sprintf("moved%d", tag)}); rec.Code != http.StatusOK {
		t.Fatalf("renaming: %d %s", rec.Code, rec.Body.String())
	}
	for _, c := range [][3]string{{person, "viewer", "1"}, {person, "editor", "1"}, {person, "owner", "2"}, {person, "viewer", "3"}} {
		if !held(c[0], c[1], c[2]) {
			t.Errorf("the person lost %s on document:%s with the name", c[1], c[2])
		}
	}
	var moved time.Time
	if err := s.db.QueryRow(ctx, `SELECT expires_at FROM core.relations WHERE org_id = $1::uuid
		AND subject_id = $2 AND relation = 'editor'`, org, person).Scan(&moved); err != nil {
		t.Fatalf("the expiring grant did not move: %v", err)
	}
	if !moved.Equal(end) {
		t.Errorf("the grant moved with expiry %v, want %v", moved, end)
	}
	var manager int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM core.relations WHERE org_id = $1::uuid
		AND object_type = 'user' AND object_id = $2`, org, person).Scan(&manager); err != nil || manager != 1 {
		t.Errorf("the relation on the person moved to %d rows (%v), want one", manager, err)
	}

	// The names' next holder starts with nothing, by either.
	next := create(address, username)
	for _, name := range []string{address, username, next} {
		for _, c := range [][2]string{{"viewer", "1"}, {"editor", "1"}, {"owner", "2"}, {"viewer", "3"}} {
			if held(name, c[0], c[1]) {
				t.Errorf("the next holder, as %s, inherited %s on document:%s", name, c[0], c[1])
			}
		}
	}
	if got, err := store.HoldsAny(ctx, s.db, org, "service", "billing", []string{"viewer"}, "document", "1", nil); err != nil || got == "" {
		t.Errorf("a service's grant went with them: %q %v", got, err)
	}
}
