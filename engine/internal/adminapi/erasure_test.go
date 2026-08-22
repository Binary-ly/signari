package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Erasure is the only operation in this API that nobody can undo, so the tests
// are mostly about refusing to do it.

// seedSubject makes a user with a subject key, and returns the subject id.
func seedSubject(t *testing.T, s *Server, active bool) string {
	t.Helper()
	ctx := context.Background()
	var subjectID string
	status := "deactivated"
	if active {
		status = "active"
	}
	err := s.db.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://er-' || gen_random_uuid() || '.test', 'T') RETURNING id
		), o AS (
			INSERT INTO core.organizations (instance_id, slug, display_name)
			SELECT id, 'e' || substr(gen_random_uuid()::text,1,8), 'Org' FROM i RETURNING id
		)
		INSERT INTO core.users (org_id, email, user_handle, status)
		SELECT id, 'e'||substr(gen_random_uuid()::text,1,8)||'@example.test',
		       decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		              md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'), $1
		FROM o RETURNING id::text`, status).Scan(&subjectID)
	if err != nil {
		t.Fatalf("seeding a user: %v", err)
	}
	// A subject key, as the MFA path would mint.
	if _, err := s.db.Exec(ctx, `
		INSERT INTO core.subject_keys (subject_id, wrapped_dek, wrap_key_ref)
		VALUES ($1::uuid, decode(md5(gen_random_uuid()::text),'hex'), 'test-root')`,
		subjectID); err != nil {
		t.Fatalf("seeding a subject key: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = s.db.Exec(c, `DELETE FROM core.subject_keys WHERE subject_id = $1::uuid`, subjectID)
		_, _ = s.db.Exec(c, `DELETE FROM core.users WHERE id = $1::uuid`, subjectID)
	})
	return subjectID
}

func erase(t *testing.T, s *Server, subjectID, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		"/admin/subjects/"+subjectID+"/erase", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// The confirmation must name WHICH subject. A boolean would be satisfied by any
// body a client sends out of habit, and by a request replayed at another path.
func TestErasureRequiresTheSubjectIdentifierAsConfirmation(t *testing.T) {
	s, _ := newTestServer(t)
	id := seedSubject(t, s, false)

	if code, body := erase(t, s, id, `{}`); code != http.StatusBadRequest {
		t.Errorf("no confirmation gave %d, want 400 (%v)", code, body)
	}
	if code, body := erase(t, s, id, `{"confirm":true}`); code != http.StatusBadRequest {
		t.Errorf("a boolean confirmation gave %d, want 400 (%v)", code, body)
	}
	// The mistake this exists to catch: a confirmation naming somebody else.
	other := seedSubject(t, s, false)
	code, body := erase(t, s, id, `{"confirm_subject_id":"`+other+`"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("a mismatched confirmation gave %d, want 400 (%v)", code, body)
	}
	if body["error"] != "confirmation_mismatch" {
		t.Errorf("error = %v, want confirmation_mismatch", body["error"])
	}

	// And neither subject was touched.
	for _, sid := range []string{id, other} {
		var erased bool
		if err := s.db.QueryRow(context.Background(),
			`SELECT erased_at IS NOT NULL FROM core.subject_keys WHERE subject_id = $1::uuid`,
			sid).Scan(&erased); err != nil {
			t.Fatal(err)
		}
		if erased {
			t.Errorf("%s was erased by a refused request", sid)
		}
	}
}

// An active account is refused, because an erased subject can never hold a key
// again — so an active account whose key is gone fails permanently rather than
// working with less data.
func TestErasingAnActiveAccountIsRefusedUnlessStated(t *testing.T) {
	s, _ := newTestServer(t)
	id := seedSubject(t, s, true)

	code, body := erase(t, s, id, `{"confirm_subject_id":"`+id+`"}`)
	if code != http.StatusConflict {
		t.Fatalf("erasing an active account gave %d, want 409 (%v)", code, body)
	}
	if body["error"] != "account_still_active" {
		t.Errorf("error = %v, want account_still_active", body["error"])
	}

	// Saying so proceeds, and deactivates in the same transaction.
	code, body = erase(t, s, id, `{"confirm_subject_id":"`+id+`","deactivate":true}`)
	if code != http.StatusOK {
		t.Fatalf("erasing with deactivate gave %d (%v)", code, body)
	}
	if body["deactivated"] != true {
		t.Errorf("deactivated = %v, want true", body["deactivated"])
	}

	var status string
	if err := s.db.QueryRow(context.Background(),
		`SELECT status FROM core.users WHERE id = $1::uuid`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "deactivated" {
		t.Errorf("account status = %q after erasure, want deactivated", status)
	}
}

// The property the whole feature exists for: the key is destroyed and the row
// survives as evidence.
func TestErasureDestroysTheKeyAndKeepsTheEvidence(t *testing.T) {
	s, _ := newTestServer(t)
	id := seedSubject(t, s, false)

	if code, body := erase(t, s, id, `{"confirm_subject_id":"`+id+`"}`); code != http.StatusOK {
		t.Fatalf("erase gave %d (%v)", code, body)
	}

	var dekPresent, erased bool
	if err := s.db.QueryRow(context.Background(), `
		SELECT wrapped_dek IS NOT NULL, erased_at IS NOT NULL
		FROM core.subject_keys WHERE subject_id = $1::uuid`, id).Scan(&dekPresent, &erased); err != nil {
		t.Fatalf("the subject_keys row is gone; it is supposed to survive as the "+
			"evidence that the erasure happened: %v", err)
	}
	if dekPresent {
		t.Error("the wrapped key survived the erasure")
	}
	if !erased {
		t.Error("erased_at was not set")
	}
}

// A repeat is a conflict, not a second success. "When was this erased" is an
// audit question, and answering 200 twice makes the two indistinguishable.
func TestASecondErasureReportsThatItAlreadyHappened(t *testing.T) {
	s, _ := newTestServer(t)
	id := seedSubject(t, s, false)

	if code, _ := erase(t, s, id, `{"confirm_subject_id":"`+id+`"}`); code != http.StatusOK {
		t.Fatalf("the first erasure failed (%d)", code)
	}
	code, body := erase(t, s, id, `{"confirm_subject_id":"`+id+`"}`)
	if code != http.StatusConflict {
		t.Fatalf("a repeated erasure gave %d, want 409 (%v)", code, body)
	}
	if body["error"] != "already_erased" {
		t.Errorf("error = %v, want already_erased", body["error"])
	}
}

// The scope is its own, so a token that may rename a user cannot destroy one.
func TestErasureNeedsItsOwnScope(t *testing.T) {
	if contains(KnownScopes, ScopeSubjectsErase) == false {
		t.Error("subjects:erase is not grantable, so no database token can ever erase")
	}
	if ScopeSubjectsErase == ScopeUsersWrite {
		t.Error("erasure shares a scope with ordinary user writes")
	}
}

func contains(hay []string, n string) bool {
	for _, h := range hay {
		if h == n {
			return true
		}
	}
	return false
}
