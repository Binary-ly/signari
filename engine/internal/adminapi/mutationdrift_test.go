package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Every mutating route must honour preconditions AND bump the configuration
// version. Neither is checkable by reading a handler, because both are
// omissions.
//
// This exists because both had already gone wrong in the same place. Before this
// change `POST /admin/subjects/{id}/erase` opened its own transaction and
// committed directly, so crypto-shredding a subject -- and, with
// `deactivate: true`, ending their account -- never bumped `core.config_version`.
// The package's own doc comment describes exactly that outcome: the write is
// durable and INVISIBLE, and running engine nodes keep serving the previous
// configuration until some unrelated write happens to move the version.
//
// It was the one handler not using the shared helper. Nothing failed, because
// nothing was looking. This is what looks.

// mutatingRoute is one route, with a body valid enough to reach the mutation.
//
// The bodies must be genuinely acceptable: the precondition is checked INSIDE
// mutateIf, which runs after request validation, so a route rejected at the body
// would report a false pass for both properties being tested.
type mutatingRoute struct {
	name   string
	method string
	// path is built per-run, because several need a fresh fixture.
	path func(t *testing.T, s *Server) string
	body func(t *testing.T, s *Server, path string) string
}

func allMutatingRoutes() []mutatingRoute {
	return []mutatingRoute{
		{
			name: "POST /admin/users", method: http.MethodPost,
			path: func(*testing.T, *Server) string { return "/admin/users" },
			body: func(t *testing.T, s *Server, _ string) string {
				return fmt.Sprintf(`{"email":"drift-%d@example.test","org_id":%q}`,
					time.Now().UnixNano(), anyOrgID(t, s))
			},
		},
		{
			name: "PATCH /admin/users/{userID}", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				return "/admin/users/" + newDriftUser(t, s)
			},
			body: func(*testing.T, *Server, string) string { return `{"active":false}` },
		},
		{
			name: "POST /admin/clients", method: http.MethodPost,
			path: func(*testing.T, *Server) string { return "/admin/clients" },
			body: func(t *testing.T, s *Server, _ string) string {
				return fmt.Sprintf(`{"client_id":"drift-%d","org_id":%q,"display_name":"d",`+
					`"redirect_uris":["https://app.example.test/cb"]}`,
					time.Now().UnixNano(), anyOrgID(t, s))
			},
		},
		{
			name: "PATCH /admin/clients/{clientID}", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				return "/admin/clients/" + newPreconditionClient(t, s)
			},
			body: func(*testing.T, *Server, string) string { return `{"enabled":false}` },
		},
		{
			name: "POST /admin/clients/{clientID}/rotate-secret", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/clients/" + newPreconditionClient(t, s) + "/rotate-secret"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "POST /admin/subjects/{subjectID}/erase", method: http.MethodPost,
			path: func(t *testing.T, s *Server) string {
				return "/admin/subjects/" + newDriftSubject(t, s) + "/erase"
			},
			body: func(t *testing.T, s *Server, path string) string {
				// confirm_subject_id must repeat the identifier in the path.
				var id string
				fmt.Sscanf(path, "/admin/subjects/%s", &id)
				id = id[:len(id)-len("/erase")]
				return fmt.Sprintf(`{"confirm_subject_id":%q,"deactivate":true}`, id)
			},
		},
		{
			name: "POST /admin/groups", method: http.MethodPost,
			path: func(*testing.T, *Server) string { return "/admin/groups" },
			body: func(t *testing.T, s *Server, _ string) string {
				return fmt.Sprintf(`{"org_id":%q,"name":"drift-%d"}`,
					anyOrgID(t, s), time.Now().UnixNano())
			},
		},
		{
			name: "PATCH /admin/groups/{groupID}", method: http.MethodPatch,
			path: func(t *testing.T, s *Server) string {
				return "/admin/groups/" + newDriftGroup(t, s)
			},
			body: func(*testing.T, *Server, string) string { return `{"display_name":"renamed"}` },
		},
		{
			name: "DELETE /admin/groups/{groupID}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/groups/" + newDriftGroup(t, s)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "PUT /admin/groups/{groupID}/members/{userID}", method: http.MethodPut,
			path: func(t *testing.T, s *Server) string {
				return "/admin/groups/" + newDriftGroup(t, s) + "/members/" + newDriftUser(t, s)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "DELETE /admin/groups/{groupID}/members/{userID}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/groups/" + newDriftGroup(t, s) + "/members/" + newDriftUser(t, s)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "DELETE /admin/users/{userID}/sessions", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/users/" + newDriftUser(t, s) + "/sessions"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name: "DELETE /admin/sessions/{sid}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/sessions/" + newDriftSession(t, s, newDriftUser(t, s))
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
	}
}

// newDriftGroup creates a group in the fixture organisation.
func newDriftGroup(t *testing.T, s *Server) string {
	t.Helper()
	var id string
	if err := s.db.QueryRow(context.Background(), `
		INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, $2, $2)
		RETURNING id::text`,
		anyOrgID(t, s), fmt.Sprintf("drift-%d", time.Now().UnixNano())).Scan(&id); err != nil {
		t.Fatalf("creating the fixture group: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.group_members WHERE group_id = $1::uuid`, id)
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.groups WHERE id = $1::uuid`, id)
	})
	return id
}

// newDriftSession creates a live session for a user.
func newDriftSession(t *testing.T, s *Server, userID string) string {
	t.Helper()
	sid := fmt.Sprintf("drift-sess-%d", time.Now().UnixNano())
	var orgID string
	if err := s.db.QueryRow(context.Background(),
		`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
		t.Fatalf("reading the fixture user's organisation: %v", err)
	}
	if _, err := s.db.Exec(context.Background(), `
		INSERT INTO core.sessions (sid, org_id, user_id, auth_time, not_after)
		VALUES ($1, $2::uuid, $3::uuid, now(), now() + interval '1 hour')`,
		sid, orgID, userID); err != nil {
		t.Fatalf("creating the fixture session: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.sessions WHERE sid = $1`, sid)
	})
	return sid
}

func newDriftUser(t *testing.T, s *Server) string {
	t.Helper()
	var id string
	if err := s.db.QueryRow(context.Background(), `
		INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, sha256($2::bytea) || sha256($3::bytea), $4)
		RETURNING id::text`,
		anyOrgID(t, s), fmt.Sprint(time.Now().UnixNano()),
		fmt.Sprint(time.Now().UnixNano()+1),
		fmt.Sprintf("drift-%d@example.test", time.Now().UnixNano())).Scan(&id); err != nil {
		t.Fatalf("creating the fixture user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, id)
	})
	return id
}

// newDriftSubject creates a subject key that erasure can destroy.
//
// Columns taken from the live schema (subject_id, wrapped_dek, wrap_key_ref),
// not from what a fixture elsewhere happens to use. The first version of this
// helper guessed `org_id` and `dek`, the insert failed, and the erasure route --
// the one whose missing version bump prompted this whole test -- skipped itself
// while the suite reported PASS. A skip in a coverage test is a hole with a
// friendly name.
func newDriftSubject(t *testing.T, s *Server) string {
	t.Helper()
	var id string
	if err := s.db.QueryRow(context.Background(), `
		INSERT INTO core.subject_keys (subject_id, wrapped_dek, wrap_key_ref)
		VALUES (gen_random_uuid(), $1, 'drift-test')
		RETURNING subject_id::text`,
		[]byte("drift-fixture-key-material")).Scan(&id); err != nil {
		t.Fatalf("creating the subject-key fixture: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.subject_keys WHERE subject_id = $1::uuid`, id)
	})
	return id
}

// Property 1: a stale If-Match must be refused, on every mutating route.
//
// 412 specifically. A 500 means the handler ran the mutation and then failed to
// map the error, which would mean the write happened.
func TestEveryMutatingRouteHonoursPreconditions(t *testing.T) {
	s, _ := newTestServer(t)

	for _, rt := range allMutatingRoutes() {
		t.Run(rt.name, func(t *testing.T) {
			path := rt.path(t, s)
			body := rt.body(t, s, path)

			before := currentVersion(t, s)
			stale := fmt.Sprintf(`"%d"`, before-1)

			rec := httptest.NewRecorder()
			s.Routes().ServeHTTP(rec, adminReq(t, rt.method, path, body, stale))

			if rec.Code != http.StatusPreconditionFailed {
				t.Fatalf("stale If-Match gave %d, want 412. This route does not thread "+
					"the precondition through to mutateIf, so a caller asking for a "+
					"conditional write gets an unconditional one: %s",
					rec.Code, rec.Body.String())
			}
			if got := currentVersion(t, s); got != before {
				t.Errorf("a refused conditional write still moved the version: %d -> %d",
					before, got)
			}
		})
	}
}

// Property 2: a successful mutation must bump the configuration version.
//
// The invariant in this package's doc comment, checked rather than asserted.
// This is the test that would have caught the erasure handler.
func TestEveryMutatingRouteBumpsTheConfigVersion(t *testing.T) {
	s, _ := newTestServer(t)

	for _, rt := range allMutatingRoutes() {
		t.Run(rt.name, func(t *testing.T) {
			path := rt.path(t, s)
			body := rt.body(t, s, path)

			before := currentVersion(t, s)

			rec := httptest.NewRecorder()
			s.Routes().ServeHTTP(rec, adminReq(t, rt.method, path, body, ""))

			if rec.Code >= 400 {
				t.Fatalf("the route did not succeed (%d), so this test proves nothing "+
					"about it. Fix the fixture rather than the assertion: %s",
					rec.Code, rec.Body.String())
			}
			after := currentVersion(t, s)
			if after <= before {
				t.Errorf("config version %d -> %d: this mutation is durable and "+
					"INVISIBLE. Engine nodes poll this counter to decide when to "+
					"reload, so a write that does not move it is applied in the "+
					"database and ignored by every running node", before, after)
			}
			// And the caller is told, so it can confirm propagation without polling.
			if tag := rec.Header().Get("ETag"); tag != fmt.Sprintf(`"%d"`, after) {
				t.Errorf("ETag = %q, want %q: a mutation that does not return its "+
					"version forces a second round trip before the next conditional "+
					"write", tag, fmt.Sprintf(`"%d"`, after))
			}
		})
	}
}
