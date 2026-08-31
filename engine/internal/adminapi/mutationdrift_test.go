package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
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
			// A fresh user each time: the route deletes what it is pointed at,
			// so reusing one would make the second assertion a 404 rather than
			// the precondition failure it is checking for.
			name: "DELETE /admin/users/{userID}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/users/" + newDriftUser(t, s)
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			// Keyed on the user, so no factor id in the path. The fixture
			// enrols TOTP first: the handler returns 404 when there was nothing
			// to remove, and a 404 would exempt this route from the very checks
			// the list exists to apply.
			name: "DELETE /admin/users/{userID}/factors/{kind}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/users/" + newDriftUserWithTOTP(t, s) + "/factors/totp"
			},
			body: func(*testing.T, *Server, string) string { return "" },
		},
		{
			name:   "DELETE /admin/users/{userID}/factors/{kind}/{factorID}",
			method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				userID := newDriftUser(t, s)
				return "/admin/users/" + userID + "/factors/webauthn/" +
					newDriftPasskey(t, s, userID)
			},
			body: func(*testing.T, *Server, string) string { return "" },
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
			name: "DELETE /admin/clients/{clientID}", method: http.MethodDelete,
			path: func(t *testing.T, s *Server) string {
				return "/admin/clients/" + newPreconditionClient(t, s)
			},
			body: func(*testing.T, *Server, string) string { return "" },
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
// newDriftUserWithTOTP creates a user who has something to reset.
//
// secret_enc is a placeholder: nothing in these tests decrypts it, and the
// factor routes deliberately never return it. Columns taken from the live
// schema rather than guessed -- a failing INSERT here would make the route skip
// itself while the suite reported PASS.
func newDriftUserWithTOTP(t *testing.T, s *Server) string {
	t.Helper()
	userID := newDriftUser(t, s)
	var orgID string
	if err := s.db.QueryRow(context.Background(),
		`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
		t.Fatalf("reading the fixture user's organisation: %v", err)
	}
	if _, err := s.db.Exec(context.Background(), `
		INSERT INTO core.totp_credentials (user_id, org_id, secret_enc, confirmed_at)
		VALUES ($1::uuid, $2::uuid, $3, now())`,
		userID, orgID, []byte("not-a-real-secret")); err != nil {
		t.Fatalf("enrolling the fixture TOTP credential: %v", err)
	}
	return userID
}

// newDriftPasskey gives a user one WebAuthn credential and returns its id.
func newDriftPasskey(t *testing.T, s *Server, userID string) string {
	t.Helper()
	var orgID string
	if err := s.db.QueryRow(context.Background(),
		`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
		t.Fatalf("reading the fixture user's organisation: %v", err)
	}
	var id string
	if err := s.db.QueryRow(context.Background(), `
		INSERT INTO core.webauthn_credentials
			(user_id, org_id, credential_id, public_key, rp_id, friendly_name)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)
		RETURNING id::text`,
		userID, orgID,
		[]byte(fmt.Sprintf("cred-%d", time.Now().UnixNano())),
		[]byte("not-a-real-key"), "localhost", "fixture key").Scan(&id); err != nil {
		t.Fatalf("enrolling the fixture passkey: %v", err)
	}
	return id
}

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
// The list below must cover every mutating route the server registers.
//
// # Why this guard is the important one
//
// `allMutatingRoutes` is hand-written, and the two tests under it are what
// guarantee the product's headline property: every administrative write honours
// an If-Match precondition and bumps the configuration version. A route missing
// from the list is not caught by those tests -- it is silently exempt from both,
// and they still report success.
//
// That is a green suite meaning less than it appears, which this codebase has
// been caught by before. Adding `DELETE /admin/clients/{clientID}` demonstrated
// it: both tests passed with the new route entirely unexercised.
//
// Derived from the actual registrations rather than a second hand-written list,
// so the only way to satisfy it is to write the case.
func TestTheMutatingRouteListCoversEveryRegisteredRoute(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}

	// mux.HandleFunc("METHOD /admin/...", ...) for the methods that write.
	re := regexp.MustCompile(`mux\.HandleFunc\("(POST|PATCH|PUT|DELETE) (/admin/[^"]*)"`)
	found := re.FindAllStringSubmatch(string(src), -1)
	if len(found) < 8 {
		t.Fatalf("only %d mutating registrations parsed out of server.go; the regex "+
			"has stopped matching and this guard is checking nothing", len(found))
	}

	listed := map[string]bool{}
	for _, rt := range allMutatingRoutes() {
		listed[rt.name] = true
	}

	var missing []string
	for _, m := range found {
		name := m[1] + " " + m[2]
		if !listed[name] {
			missing = append(missing, "  "+name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d mutating route(s) are registered but absent from "+
			"allMutatingRoutes():\n%s\n\nEach is currently exempt from both the "+
			"precondition test and the config-version test, and those tests pass "+
			"without exercising it. Add a case rather than trusting the route.",
			len(missing), strings.Join(missing, "\n"))
	}
}

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
