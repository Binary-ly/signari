package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"signari.dev/engine/internal/audit"
)

// Reading the audit trail over HTTP.
//
// The two properties worth testing are the ones that are wrong by default:
// a page boundary that skips rows, and an organisation boundary that leaks.

type auditPage struct {
	Events []struct {
		ID         string          `json:"id"`
		OrgID      string          `json:"org_id"`
		EventType  string          `json:"event_type"`
		SubjectID  string          `json:"subject_id"`
		OccurredAt string          `json:"occurred_at"`
		Detail     json.RawMessage `json:"detail"`
	} `json:"events"`
	NextCursor    string `json:"next_cursor"`
	ChainVerified bool   `json:"chain_verified"`
}

func getAuditPage(t *testing.T, s *Server, query string) auditPage {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodGet, "/admin/audit-events"+query, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("audit read gave %d: %s", rec.Code, rec.Body.String())
	}
	var page auditPage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	return page
}

// Paging must not skip rows that share a timestamp.
//
// # Why this is the test that matters
//
// A fan-out writes several audit events inside ONE transaction, so they land
// with identical `occurred_at` values. A cursor on `occurred_at` alone then has
// no way to say "after this one" without either repeating rows or skipping
// them — and the failure is silent, because the page that loses a row still
// looks like a page.
//
// The cursor is therefore the pair `(occurred_at, id)`, which is unique because
// id is. This test writes several events with an identical timestamp and pages
// through them one at a time, which is the smallest page size that can expose
// the bug.
func TestPagingTheAuditTrailDoesNotSkipRowsSharingATimestamp(t *testing.T) {
	s, _ := newTestServer(t)
	userID := newDriftUser(t, s)
	orgID := anyOrgID(t, s)

	// Five events written through audit.Write, in ONE transaction so they share
	// a timestamp -- which is the condition this test exists for.
	//
	// Written properly, and never deleted afterwards. The first version
	// fabricated rows with hand-made prev_hash/entry_hash values and cleaned up
	// with DELETE, and both halves were wrong: the fabricated hashes were not
	// chain links, and deleting from a hash chain BREAKS it. It corrupted the
	// shared database's chain and failed the audit package's own
	// tamper-detection tests, which is precisely what those tests are for.
	marker := fmt.Sprintf("paging-%d", time.Now().UnixNano())
	writeFixtureEvents(t, s, orgID, userID, marker, 5)

	seen := map[string]bool{}
	cursor := ""
	for range 10 { // bounded, so a broken cursor loops finitely
		q := "?limit=1&event_type=" + marker
		if cursor != "" {
			q += "&cursor=" + cursor
		}
		page := getAuditPage(t, s, q)
		for _, e := range page.Events {
			if seen[e.ID] {
				t.Fatalf("event %s was returned on two pages; the cursor repeats rows", e.ID)
			}
			seen[e.ID] = true
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	if len(seen) != 5 {
		t.Fatalf("paged one at a time and saw %d of 5 events sharing a timestamp. "+
			"A cursor on occurred_at alone silently drops rows at every page "+
			"boundary, and the short page still looks like a page.", len(seen))
	}
}

// A scoped token must not read another organisation's trail.
//
// The restriction is in the WHERE clause rather than applied to the result, for
// the reason the rest of this API states: a filter applied afterwards is one a
// later refactor moves or drops, and the failure is one tenant reading another's
// authentication history while the endpoint returns a cheerful 200.
func TestAScopedTokenCannotReadAnotherOrganisationsAuditTrail(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()

	other := makeOrg(t, s, fmt.Sprintf("audit-other-%d", time.Now().UnixNano()))
	marker := fmt.Sprintf("foreign-%d", time.Now().UnixNano())
	writeFixtureEvents(t, s, other, "", marker, 1)

	// A principal scoped to a DIFFERENT organisation.
	scoped := &Principal{OrgID: anyOrgID(t, s), Scopes: []string{ScopeAuditRead}}
	r := httptest.NewRequest(http.MethodGet,
		"/admin/audit-events?event_type="+marker, nil).
		WithContext(withPrincipal(ctx, scoped))

	rec := httptest.NewRecorder()
	s.listAuditEvents(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("gave %d: %s", rec.Code, rec.Body.String())
	}

	var page auditPage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 0 {
		t.Fatalf("a token scoped to one organisation read %d events belonging to "+
			"another. This is the silent kind of leak: the endpoint answered 200.",
			len(page.Events))
	}
}

// Every response states that it did not verify the chain.
//
// Not left to the documentation. Somebody will build a compliance process on
// this endpoint, and the place they will look is the response.
func TestTheAuditReadDeclaresThatItDoesNotVerifyTheChain(t *testing.T) {
	s, _ := newTestServer(t)
	page := getAuditPage(t, s, "?limit=1")
	if page.ChainVerified {
		t.Fatal("the response claims the chain was verified. A page cannot be " +
			"verified in isolation -- its first entry's predecessor is not in it.")
	}
}

// A malformed cursor or timestamp is a 400, not a 500.
func TestMalformedAuditQueriesAreRefusedClearly(t *testing.T) {
	s, _ := newTestServer(t)
	for _, q := range []string{
		"?cursor=not-a-cursor",
		"?since=yesterday",
		"?until=2026-13-45",
	} {
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, http.MethodGet, "/admin/audit-events"+q, "", ""))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s gave %d, want 400: %s", q, rec.Code, rec.Body.String())
		}
	}
}

// The time bounds actually bound.
func TestAuditTimeFiltersApply(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	orgID := anyOrgID(t, s)
	marker := fmt.Sprintf("timed-%d", time.Now().UnixNano())

	// Written properly, then BACKDATED with an UPDATE of occurred_at only.
	//
	// occurred_at is not part of the chain hash, so moving it leaves every link
	// intact -- which is the only way to age a row without forging one. An
	// INSERT with hand-made hashes would break the chain, and a DELETE
	// afterwards would break it again.
	writeFixtureEvents(t, s, orgID, "", marker, 1)
	if _, err := s.db.Exec(ctx, `
		UPDATE core.audit_events SET occurred_at = now() - interval '72 hours'
		WHERE event_type = $1`, marker); err != nil {
		t.Fatal(err)
	}

	within := getAuditPage(t, s, "?event_type="+marker+
		"&since="+time.Now().UTC().Add(-96*time.Hour).Format(time.RFC3339))
	if len(within.Events) != 1 {
		t.Errorf("since=96h ago returned %d events, want 1", len(within.Events))
	}

	after := getAuditPage(t, s, "?event_type="+marker+
		"&since="+time.Now().UTC().Add(-1*time.Hour).Format(time.RFC3339))
	if len(after.Events) != 0 {
		t.Errorf("since=1h ago returned %d events for a 72-hour-old row, want 0",
			len(after.Events))
	}
}

// writeFixtureEvents appends real audit events through audit.Write.
//
// # Why not an INSERT
//
// core.audit_events is a HASH CHAIN. Each row's entry_hash covers its
// predecessor's, so a row inserted with a hand-made hash is not a link, and a
// row deleted afterwards breaks the link that pointed at it. The first version
// of these fixtures did both, corrupted the shared database's chain, and failed
// the audit package's own tamper-detection tests — which is exactly what those
// tests exist to catch, so the mechanism worked and the fixtures were wrong.
//
// Nothing is cleaned up, and that is correct rather than lazy: an append-only
// trail is append-only for tests too. `occurred_at` may be moved afterwards
// because it is not part of the hash (see audit.chainHash); nothing else may.
//
// All `count` events are written in ONE transaction, so they share an
// occurred_at — which is the condition the paging test needs, and the reason a
// cursor on the timestamp alone would drop rows.
func writeFixtureEvents(t *testing.T, s *Server, orgID, subjectID, eventType string, count int) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatalf("beginning the fixture transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for i := 0; i < count; i++ {
		if err := audit.Write(ctx, tx, audit.Event{
			Type: eventType, OrgID: orgID, SubjectID: subjectID,
			Detail: map[string]any{"n": i},
		}); err != nil {
			t.Fatalf("writing fixture event %d: %v", i, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("committing the fixture events: %v", err)
	}
}
