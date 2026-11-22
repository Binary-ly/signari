package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// POST /admin/batch (6.08): all or none, one bump, each operation held to its
// own scope.

func batchBody(t *testing.T, ops ...map[string]any) map[string]any {
	t.Helper()
	return map[string]any{"operations": ops}
}

func TestAHundredOperationBatchIsAtomic(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := anyOrgID(t, s)
	stamp := time.Now().UnixNano()
	email := func(i int) string { return fmt.Sprintf("batch-%d-%03d@example.test", stamp, i) }
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE email LIKE $1`,
			fmt.Sprintf("batch-%d-%%", stamp))
	})
	ops := func(bad bool) []map[string]any {
		out := make([]map[string]any, 0, 100)
		for i := 0; i < 100; i++ {
			out = append(out, map[string]any{"method": "POST", "path": "/admin/users",
				"body": map[string]any{"org_id": org, "email": email(i)}})
		}
		if bad {
			// The last one names an organisation that does not exist.
			out[99]["body"] = map[string]any{"org_id": "00000000-0000-0000-0000-000000000000", "email": email(99)}
		}
		return out
	}
	made := func() int {
		var n int
		_ = s.db.QueryRow(ctx, `SELECT count(*) FROM core.users WHERE email LIKE $1`,
			fmt.Sprintf("batch-%d-%%", stamp)).Scan(&n)
		return n
	}

	before := currentVersion(t, s)
	rec := call(t, s, http.MethodPost, "/admin/batch", testToken, map[string]any{"operations": ops(true)})
	var refused map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &refused)
	if rec.Code < 400 || refused["error"] != "batch_failed" || refused["failed_index"] != float64(99) {
		t.Fatalf("a batch whose last operation fails answered %d %s", rec.Code, truncate(rec.Body.String(), 200))
	}
	if n := made(); n != 0 {
		t.Fatalf("a refused batch kept %d of its 99 good writes", n)
	}

	rec = call(t, s, http.MethodPost, "/admin/batch", testToken, map[string]any{"operations": ops(false)})
	var done struct {
		ConfigVersion int64 `json:"config_version"`
		Results       []batchResult
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &done)
	if rec.Code != http.StatusOK || len(done.Results) != 100 || made() != 100 {
		t.Fatalf("a good batch: %d, %d results, %d made", rec.Code, len(done.Results), made())
	}
	// One bump for the hundred, which every operation reported as its own.
	for i, r := range done.Results {
		var body struct {
			ConfigVersion int64 `json:"config_version"`
		}
		_ = json.Unmarshal(r.Body, &body)
		if r.Status != http.StatusCreated || body.ConfigVersion != done.ConfigVersion {
			t.Errorf("operation %d answered %d at version %d, the batch committed %d", i, r.Status,
				body.ConfigVersion, done.ConfigVersion)
			break
		}
	}
	if done.ConfigVersion <= before || rec.Header().Get("ETag") != fmt.Sprintf(`"%d"`, done.ConfigVersion) {
		t.Errorf("the batch committed %d (from %d) and tagged %s", done.ConfigVersion, before, rec.Header().Get("ETag"))
	}
}

// A batch widens nothing: an operation the token may not do is refused, as it
// would be alone, and takes the batch with it.
func TestEachBatchOperationIsHeldToItsOwnScope(t *testing.T) {
	s, _ := newTestServer(t)
	usersOnly := mintToken(t, s, "batch-users-only", "", []string{ScopeUsersWrite}, nil)
	org := anyOrgID(t, s)
	email := fmt.Sprintf("batch-scope-%d@example.test", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE email = $1`, email)
	})
	rec := call(t, s, http.MethodPost, "/admin/batch", usersOnly, batchBody(t,
		map[string]any{"method": "POST", "path": "/admin/users", "body": map[string]any{"org_id": org, "email": email}},
		map[string]any{"method": "PATCH", "path": "/admin/clients/" + newPreconditionClient(t, s),
			"body": map[string]any{"enabled": false}}))
	var refused map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &refused)
	if rec.Code != http.StatusForbidden || refused["failed_index"] != float64(1) {
		t.Errorf("a clients write in a users-only token's batch answered %d %s", rec.Code, rec.Body.String())
	}
	var n int
	_ = s.db.QueryRow(context.Background(), `SELECT count(*) FROM core.users WHERE email = $1`, email).Scan(&n)
	if n != 0 {
		t.Error("the user the batch made before its refused operation was kept")
	}
	for name, body := range map[string]map[string]any{
		"a read":        batchBody(t, map[string]any{"method": "GET", "path": "/admin/users"}),
		"a batch":       batchBody(t, map[string]any{"method": "POST", "path": "/admin/batch", "body": map[string]any{}}),
		"elsewhere":     batchBody(t, map[string]any{"method": "POST", "path": "/oauth2/token"}),
		"no operations": batchBody(t),
	} {
		if rec := call(t, s, http.MethodPost, "/admin/batch", testToken, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s in a batch answered %d", name, rec.Code)
		}
	}
}

// Every write the API has is atomic inside a batch: on its own in a batch it
// writes, and beside an operation that fails it writes nothing. Counted by the
// audit records its token leaves, which only this test's token makes.
func TestEveryWriteIsAtomicInsideABatch(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	tokenName := fmt.Sprintf("batch-atomic-%d", time.Now().UnixNano())
	secret, tokenID, err := NewToken(ctx, s.db, tokenName, "", KnownScopes, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE id = $1::uuid`, tokenID)
	})
	recorded := func() int {
		var n int
		_ = s.db.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE admin_token_id = $1::uuid`, tokenID).Scan(&n)
		return n
	}
	batch := func(ops []map[string]any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]any{"operations": ops})
		r := httptest.NewRequest(http.MethodPost, "/admin/batch", strings.NewReader(string(b)))
		r.Header.Set("Authorization", "Bearer "+secret)
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, r)
		return rec
	}
	failing := map[string]any{"method": "PATCH", "path": "/admin/clients/no-such-client-anywhere",
		"body": map[string]any{"enabled": false}}

	for _, rt := range allMutatingRoutes() {
		if rt.name == "POST /admin/batch" {
			continue
		}
		op := func() map[string]any {
			path := rt.path(t, s)
			o := map[string]any{"method": rt.method, "path": path}
			if body := rt.body(t, s, path); body != "" {
				o["body"] = json.RawMessage(body)
			}
			return o
		}
		before := recorded()
		if rec := batch([]map[string]any{op(), failing}); rec.Code < 400 {
			t.Errorf("%s: a batch with a failing operation answered %d", rt.name, rec.Code)
			continue
		}
		if after := recorded(); after != before {
			t.Errorf("%s wrote %d audit record(s) in a batch that was refused", rt.name, after-before)
		}
		rec := batch([]map[string]any{op()})
		if rec.Code != http.StatusOK {
			t.Errorf("%s alone in a batch answered %d %s", rt.name, rec.Code, truncate(rec.Body.String(), 200))
			continue
		}
		if recorded() == before {
			t.Errorf("%s wrote no audit record, so this test cannot see whether a refusal undid it", rt.name)
		}
	}
}
