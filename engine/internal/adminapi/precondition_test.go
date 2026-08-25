package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Conditional writes on the administrative API.
//
// The claim being tested is not "the header is parsed". It is that a lost update
// -- two administrators editing one object, the second silently discarding the
// first's change -- is REFUSED rather than committed. Every test below is written
// so that it fails if the precondition is removed.
//
// The property is worth testing this hard because it is unusual: a survey of the
// comparable self-hosted identity providers, read against current upstream source
// on 25 August 2026, found no administrative API in the field that accepts a
// precondition on a write. So this is a guarantee being established rather than
// a convention being followed, and nothing external will notice if it regresses.

// adminReq builds an authenticated request, optionally conditional.
func adminReq(t *testing.T, method, path, body, ifMatch string) *http.Request {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Authorization", "Bearer "+testToken)
	if ifMatch != "" {
		r.Header.Set("If-Match", ifMatch)
	}
	return r
}

// currentVersion reads the live configuration version straight from the database,
// so a test never has to trust the API to tell it what the API did.
func currentVersion(t *testing.T, s *Server) int64 {
	t.Helper()
	var v int64
	if err := s.db.QueryRow(context.Background(),
		`SELECT version FROM core.config_version`).Scan(&v); err != nil {
		t.Fatalf("reading config version: %v", err)
	}
	return v
}

// newPreconditionClient creates a confidential client to edit, and returns its id.
func newPreconditionClient(t *testing.T, s *Server) string {
	t.Helper()
	id := fmt.Sprintf("pre-%d", time.Now().UnixNano())
	orgID := anyOrgID(t, s)
	if _, err := s.db.Exec(context.Background(), `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, enabled)
		VALUES ($1, $2::uuid, 'precondition fixture', 'confidential', 'x', true)`,
		id, orgID); err != nil {
		t.Fatalf("creating the fixture client: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
	})
	return id
}

func anyOrgID(t *testing.T, s *Server) string {
	t.Helper()
	var org string
	if err := s.db.QueryRow(context.Background(),
		`SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&org); err != nil {
		t.Fatalf("no organisation to hang a fixture off: %v", err)
	}
	return org
}

func clientEnabled(t *testing.T, s *Server, clientID string) bool {
	t.Helper()
	var enabled bool
	if err := s.db.QueryRow(context.Background(),
		`SELECT enabled FROM core.clients WHERE client_id = $1`, clientID).Scan(&enabled); err != nil {
		t.Fatalf("reading the client: %v", err)
	}
	return enabled
}

// THE test. Two administrators, one object, both working from the same read.
//
// Without a precondition the second write wins and the first administrator's
// change is gone with no error anywhere -- which is what every competitor
// surveyed does. With one, the second is refused and told what the version
// actually is, so it can re-read and decide.
func TestAConcurrentEditIsRefusedRatherThanSilentlyOverwriting(t *testing.T) {
	s, _ := newTestServer(t)
	clientID := newPreconditionClient(t, s)

	// Both administrators read the same version.
	shared := currentVersion(t, s)
	tag := fmt.Sprintf(`"%d"`, shared)

	// Administrator A disables the client. Administrator B, from the same read,
	// enables it. Run genuinely concurrently.
	type outcome struct {
		code int
		body string
	}
	var mu sync.Mutex
	results := map[string]outcome{}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for name, enabled := range map[string]bool{"A": false, "B": true} {
		wg.Add(1)
		go func(name string, enabled bool) {
			defer wg.Done()
			<-start // release both at once
			rec := httptest.NewRecorder()
			s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPatch,
				"/admin/clients/"+clientID,
				fmt.Sprintf(`{"enabled":%t}`, enabled), tag))
			mu.Lock()
			results[name] = outcome{rec.Code, rec.Body.String()}
			mu.Unlock()
		}(name, enabled)
	}
	close(start)
	wg.Wait()

	var ok, refused int
	for name, r := range results {
		switch r.code {
		case http.StatusOK:
			ok++
		case http.StatusPreconditionFailed:
			refused++
		default:
			t.Errorf("administrator %s got %d, which is neither success nor a "+
				"precondition failure: %s", name, r.code, r.body)
		}
	}

	if ok != 1 || refused != 1 {
		t.Fatalf("exactly one writer must win and one must be refused; got %d ok "+
			"and %d refused. Both succeeding is the lost update this exists to "+
			"prevent: %+v", ok, refused, results)
	}

	// And the surviving state must be the winner's, not a blend or the loser's.
	final := currentVersion(t, s)
	if final != shared+1 {
		t.Errorf("config version = %d, want %d: exactly one mutation should have "+
			"committed", final, shared+1)
	}
}

// The mirror, and the reason the test above is not measuring something else.
//
// WITHOUT If-Match the same two writes both succeed and one change is lost. This
// is the behaviour every surveyed competitor has, it stays the default here for
// compatibility, and pinning it proves the test above is exercising the
// precondition rather than some incidental serialisation.
func TestWithoutIfMatchTheSecondWriteSilentlyWins(t *testing.T) {
	s, _ := newTestServer(t)
	clientID := newPreconditionClient(t, s)

	first := httptest.NewRecorder()
	s.Routes().ServeHTTP(first, adminReq(t, http.MethodPatch,
		"/admin/clients/"+clientID, `{"enabled":false}`, ""))
	if first.Code != http.StatusOK {
		t.Fatalf("first write: %d %s", first.Code, first.Body.String())
	}

	second := httptest.NewRecorder()
	s.Routes().ServeHTTP(second, adminReq(t, http.MethodPatch,
		"/admin/clients/"+clientID, `{"enabled":true}`, ""))
	if second.Code != http.StatusOK {
		t.Fatalf("second write: %d %s", second.Code, second.Body.String())
	}

	if !clientEnabled(t, s, clientID) {
		t.Fatal("the second unconditional write did not win; this test no longer " +
			"describes the unconditional path")
	}
}

// A refused precondition must leave the database untouched.
//
// A 412 that arrives after the write has committed is worse than no precondition
// at all, because the caller is told it failed while the change is live.
func TestARefusedPreconditionWritesNothing(t *testing.T) {
	s, _ := newTestServer(t)
	clientID := newPreconditionClient(t, s)

	before := currentVersion(t, s)
	enabledBefore := clientEnabled(t, s, clientID)

	stale := fmt.Sprintf(`"%d"`, before-1)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPatch,
		"/admin/clients/"+clientID, `{"enabled":false}`, stale))

	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412: %s", rec.Code, rec.Body.String())
	}
	if got := currentVersion(t, s); got != before {
		t.Errorf("config version moved from %d to %d on a refused write", before, got)
	}
	if clientEnabled(t, s, clientID) != enabledBefore {
		t.Error("the client was modified by a write that returned 412")
	}
}

// The failure names both versions, because "someone else changed it" is not
// something an operator can act on.
func TestAPreconditionFailureReportsBothVersions(t *testing.T) {
	s, _ := newTestServer(t)
	clientID := newPreconditionClient(t, s)
	before := currentVersion(t, s)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPatch,
		"/admin/clients/"+clientID, `{"enabled":false}`, `"1"`))

	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412", rec.Code)
	}
	var body struct {
		Error    string `json:"error"`
		Expected int64  `json:"expected_version"`
		Current  int64  `json:"current_version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the failure: %v", err)
	}
	if body.Error != "precondition_failed" || body.Expected != 1 || body.Current != before {
		t.Errorf("body = %+v, want precondition_failed expected=1 current=%d",
			body, before)
	}
	// The current version also travels as an ETag, so a retry can use the
	// response directly rather than parsing prose.
	if got := rec.Header().Get("ETag"); got != fmt.Sprintf(`"%d"`, before) {
		t.Errorf("ETag on the failure = %q, want %q", got, fmt.Sprintf(`"%d"`, before))
	}
}

// A malformed If-Match is REFUSED, never ignored.
//
// This is the one that matters most for safety. A caller sending `If-Match: 42`
// (unquoted, which RFC 7232 does not permit) believes it has protection; ignoring
// the header would hand it a last-write-wins update wearing the appearance of a
// conditional one.
func TestAMalformedIfMatchIsRefusedNotIgnored(t *testing.T) {
	s, _ := newTestServer(t)
	clientID := newPreconditionClient(t, s)

	for _, tc := range []struct{ name, header string }{
		{"unquoted", `42`},
		{"weak validator", `W/"42"`},
		{"not a number", `"not-a-version"`},
		{"a list", `"1", "2"`},
		{"empty quotes", `""`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := currentVersion(t, s)
			rec := httptest.NewRecorder()
			s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPatch,
				"/admin/clients/"+clientID, `{"enabled":false}`, tc.header))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("If-Match %s gave %d, want 400. Ignoring a malformed "+
					"precondition performs an unconditional write for a caller that "+
					"asked for a conditional one: %s", tc.header, rec.Code, rec.Body.String())
			}
			if got := currentVersion(t, s); got != before {
				t.Errorf("a malformed If-Match still wrote: version %d -> %d", before, got)
			}
		})
	}
}

// `If-Match: *` means "if any representation exists", per RFC 7232 section 3.1.
func TestIfMatchStarProceeds(t *testing.T) {
	s, _ := newTestServer(t)
	clientID := newPreconditionClient(t, s)
	before := currentVersion(t, s)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPatch,
		"/admin/clients/"+clientID, `{"enabled":false}`, "*"))

	if rec.Code != http.StatusOK {
		t.Fatalf("If-Match: * gave %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := currentVersion(t, s); got != before+1 {
		t.Errorf("version %d -> %d, want one bump", before, got)
	}
}

// The ETag a response carries must be usable as the next request's If-Match.
//
// Without this the protocol needs an extra round trip to GET the version after
// every write, which is what makes conditional requests unusable in a loop.
func TestTheETagFromAWriteIsAcceptedAsTheNextIfMatch(t *testing.T) {
	s, _ := newTestServer(t)
	clientID := newPreconditionClient(t, s)

	first := httptest.NewRecorder()
	s.Routes().ServeHTTP(first, adminReq(t, http.MethodPatch,
		"/admin/clients/"+clientID, `{"enabled":false}`, "*"))
	if first.Code != http.StatusOK {
		t.Fatalf("first write: %d", first.Code)
	}
	tag := first.Header().Get("ETag")
	if tag == "" {
		t.Fatal("a successful mutation returned no ETag, so a caller cannot make " +
			"the next request conditional without a second round trip")
	}

	second := httptest.NewRecorder()
	s.Routes().ServeHTTP(second, adminReq(t, http.MethodPatch,
		"/admin/clients/"+clientID, `{"enabled":true}`, tag))
	if second.Code != http.StatusOK {
		t.Fatalf("chaining the returned ETag gave %d, want 200: %s",
			second.Code, second.Body.String())
	}
}

// GET /admin/config-version is the read half of the protocol and must carry the
// tag a caller sends back.
func TestConfigVersionCarriesAnETag(t *testing.T) {
	s, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodGet, "/admin/config-version", "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	want := fmt.Sprintf(`"%d"`, currentVersion(t, s))
	if got := rec.Header().Get("ETag"); got != want {
		t.Errorf("ETag = %q, want %q", got, want)
	}
}
