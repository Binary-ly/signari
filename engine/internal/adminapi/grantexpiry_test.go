package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/store"
)

// A grant made through the API with an end stops counting at that end, and one
// whose end has passed is refused rather than stored: it would read as done and
// grant nothing. Granting the tuple again decides the expiry afresh.
func TestARelationGrantedForAWhileEnds(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	m, err := authzen.ParseModel([]byte(umaModel))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveModel(ctx, s.db, org, umaModel, m, ""); err != nil {
		t.Fatal(err)
	}
	path := "/admin/organizations/" + org + "/relations"
	tuple := func(extra map[string]any) map[string]any {
		body := map[string]any{"subject": "user:temp", "relation": "viewer", "object": "document:1"}
		for k, v := range extra {
			body[k] = v
		}
		return body
	}
	holds := func() bool {
		t.Helper()
		held, err := store.HoldsAny(ctx, s.db, org, "user", "temp", []string{"viewer"}, "document", "1", nil)
		if err != nil {
			t.Fatal(err)
		}
		return held != ""
	}

	rec := call(t, s, http.MethodPut, path, testToken, tuple(map[string]any{"expires_at": time.Now().Add(-time.Minute)}))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusBadRequest || out["error"] != "invalid_expiry" || holds() {
		t.Fatalf("an end already passed answered %d %v, held %v", rec.Code, out, holds())
	}

	end := time.Now().Add(time.Second)
	rec = call(t, s, http.MethodPut, path, testToken, tuple(map[string]any{"expires_at": end}))
	out = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || out["expires_at"] == nil || !holds() {
		t.Fatalf("granting for a second answered %d %v, held %v", rec.Code, out, holds())
	}
	time.Sleep(time.Until(end) + 100*time.Millisecond)
	if holds() {
		t.Error("the grant outlived its end")
	}

	if rec := call(t, s, http.MethodPut, path, testToken, tuple(nil)); rec.Code != http.StatusOK || !holds() {
		t.Fatalf("granting again with no end answered %d, held %v", rec.Code, holds())
	}
	var expires *time.Time
	if err := s.db.QueryRow(ctx, `SELECT expires_at FROM core.relations WHERE org_id = $1::uuid AND subject_id = 'temp'`,
		org).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	if expires != nil {
		t.Errorf("granting with no end left the old one, %v", expires)
	}
}

// Approving a request for a while grants for a while, on every resource it names.
func TestAnApprovedRequestCanBeGrantedForAWhile(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	orgID, requestID, person := newDriftUMARequest(t, s)
	approve := "/admin/organizations/" + orgID + "/uma/requests/" + requestID + "/approve"

	if rec := call(t, s, http.MethodPost, approve, testToken, map[string]any{"relation": "viewer",
		"expires_at": time.Now().Add(-time.Minute)}); rec.Code != http.StatusBadRequest {
		t.Fatalf("an end already passed answered %d", rec.Code)
	}
	if p, _ := store.PendingRequestByID(ctx, s.db, requestID); p.State != "pending" {
		t.Fatalf("a refused approval left the request %s", p.State)
	}

	end := time.Now().Add(time.Second)
	if rec := call(t, s, http.MethodPost, approve, testToken, map[string]any{"relation": "viewer",
		"expires_at": end}); rec.Code != http.StatusOK {
		t.Fatalf("approving: %d %s", rec.Code, rec.Body.String())
	}
	holds := func() string {
		t.Helper()
		held, err := store.HoldsAny(ctx, s.db, orgID, "user", person, []string{"viewer"}, "document", "42", nil)
		if err != nil {
			t.Fatal(err)
		}
		return held
	}
	if holds() != "viewer" {
		t.Fatal("the approval granted nothing")
	}
	time.Sleep(time.Until(end) + 100*time.Millisecond)
	if got := holds(); got != "" {
		t.Errorf("the approved grant outlived its end, holding %q", got)
	}
}

// The person who decided is who granted: a relation is a privilege grant and
// needs the provenance of one.
func TestWhoApprovedARequestIsWhoGrantedIt(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	orgID, requestID, person := newDriftUMARequest(t, s)
	var decider string
	if err := s.db.QueryRow(ctx, `SELECT id::text FROM core.users WHERE email = $1`, person).Scan(&decider); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.ApproveUMARequest(ctx, tx, orgID, requestID, "viewer", decider, nil); err != nil {
		t.Fatal(err)
	}
	var by string
	if err := tx.QueryRow(ctx, `SELECT granted_by::text FROM core.relations
		WHERE org_id = $1::uuid AND object_id = '42'`, orgID).Scan(&by); err != nil {
		t.Fatal(err)
	}
	if by != decider {
		t.Errorf("granted_by is %q, want the decider %q", by, decider)
	}
}
