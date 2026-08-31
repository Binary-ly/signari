package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
	ctx := context.Background()
	userID := newDriftUser(t, s)
	orgID := anyOrgID(t, s)

	// Five events, one timestamp, written directly so the timestamp really is
	// identical rather than merely close.
	stamp := time.Now().UTC()
	marker := fmt.Sprintf("paging-%d", stamp.UnixNano())
	for i := 0; i < 5; i++ {
		if _, err := s.db.Exec(ctx, `
			INSERT INTO core.audit_events
				(org_id, occurred_at, event_type, subject_id, detail, prev_hash, entry_hash)
			VALUES ($1::uuid, $2::timestamptz, $3::text, $4::uuid,
			        jsonb_build_object('n', $5::int),
			        sha256($6::bytea), sha256($7::bytea))`,
			orgID, stamp, marker, userID, i,
			[]byte(marker), []byte(fmt.Sprintf("%s-%d", marker, i))); err != nil {
			t.Fatalf("writing fixture event %d: %v", i, err)
		}
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.audit_events WHERE event_type = $1`, marker)
	})

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
	if _, err := s.db.Exec(ctx, `
		INSERT INTO core.audit_events
			(org_id, occurred_at, event_type, detail, prev_hash, entry_hash)
		VALUES ($1::uuid, now(), $2::text, '{}'::jsonb, sha256($3::bytea), sha256($4::bytea))`,
		other, marker, []byte(marker), []byte(marker+"x")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.audit_events WHERE event_type = $1`, marker)
	})

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

	old := time.Now().UTC().Add(-72 * time.Hour)
	if _, err := s.db.Exec(ctx, `
		INSERT INTO core.audit_events
			(org_id, occurred_at, event_type, detail, prev_hash, entry_hash)
		VALUES ($1::uuid, $2::timestamptz, $3::text, '{}'::jsonb,
		        sha256($4::bytea), sha256($5::bytea))`,
		orgID, old, marker, []byte(marker), []byte(marker+"y")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.audit_events WHERE event_type = $1`, marker)
	})

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
