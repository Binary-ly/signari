package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// An operator exports a person (5.08): only with subjects:export, only within a
// scoped token's organisation, and recorded with the token that did it.
func TestAnOperatorExportsAPerson(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID := newDriftUser(t, s)
	path := "/admin/subjects/" + userID + "/export"

	exporter := mintToken(t, s, "exporter", "", []string{ScopeSubjectsExport}, nil)
	rec := call(t, s, http.MethodGet, path, exporter, nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("export: %d %q: %s", rec.Code, rec.Header().Get("Cache-Control"), rec.Body.String())
	}
	var exp store.SubjectExport
	if err := json.Unmarshal(rec.Body.Bytes(), &exp); err != nil {
		t.Fatal(err)
	}
	if exp.SubjectID != userID || len(exp.Tables["users"]) != 1 {
		t.Fatalf("the document is not this person's: %s, %d account rows", exp.SubjectID, len(exp.Tables["users"]))
	}
	var recorded int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM core.audit_events
		WHERE subject_id = $1::uuid AND event_type = 'admin.subject_exported'
		  AND admin_token_id IS NOT NULL AND detail->>'via' = 'admin_api' AND detail->>'actor' = 'exporter'`,
		userID).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != 1 {
		t.Errorf("the export was recorded %d time(s) with its token, want 1", recorded)
	}

	// Looking a person up, and reading the trail, are not taking all of them.
	reader := mintToken(t, s, "reader", "", []string{ScopeUsersWrite, ScopeAuditRead}, nil)
	if rec := call(t, s, http.MethodGet, path, reader, nil); rec.Code != http.StatusForbidden {
		t.Errorf("users:write with audit:read exported a person: %d", rec.Code)
	}

	// A token scoped to another organisation is refused; one scoped to theirs is not.
	var otherOrg, theirOrg string
	if err := s.db.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, $1, 'other' FROM core.organizations ORDER BY created_at LIMIT 1
		RETURNING id::text`, fmt.Sprintf("export-other-%d", time.Now().UnixNano())).Scan(&otherOrg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.organizations WHERE id = $1::uuid`, otherOrg)
	})
	if err := s.db.QueryRow(ctx, `SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).
		Scan(&theirOrg); err != nil {
		t.Fatal(err)
	}
	elsewhere := mintToken(t, s, "elsewhere", otherOrg, []string{ScopeSubjectsExport}, nil)
	if rec := call(t, s, http.MethodGet, path, elsewhere, nil); rec.Code == http.StatusOK {
		t.Errorf("a token scoped to another organisation exported this person: %s", rec.Body.String())
	}
	theirs := mintToken(t, s, "theirs", theirOrg, []string{ScopeSubjectsExport}, nil)
	if rec := call(t, s, http.MethodGet, path, theirs, nil); rec.Code != http.StatusOK {
		t.Errorf("a token scoped to their organisation was refused: %d %s", rec.Code, rec.Body.String())
	}

	// Nobody, and no account left: a scoped token cannot name an organisation.
	nobody := "/admin/subjects/00000000-0000-4000-8000-000000000000/export"
	if rec := call(t, s, http.MethodGet, nobody, exporter, nil); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown subject: %d, want 404", rec.Code)
	}
	if rec := call(t, s, http.MethodGet, nobody, theirs, nil); rec.Code == http.StatusOK || rec.Code == http.StatusNotFound {
		t.Errorf("a scoped token was answered about a subject with no organisation: %d", rec.Code)
	}
}
