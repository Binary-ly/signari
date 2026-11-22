package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ASVS 5.0.0 V2.3.5 (specs/asvs-5.0.0.txt:1570-1573): high-value business
// logic flows require multi-user approval. An organisation names the kinds in
// approvals_required; such a request waits, and somebody else who may make it
// approves it, which replays it as theirs.

func approvalToken(t *testing.T, s *Server, org, name string, scopes ...string) string {
	t.Helper()
	secret, id, err := NewToken(context.Background(), s.db, name+"-"+org[:8], org, scopes, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE id::text = $1`, id)
	})
	return secret
}

func decoded(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

func requireApprovals(t *testing.T, s *Server, org string, kinds ...string) {
	t.Helper()
	if rec := call(t, s, http.MethodPatch, "/admin/organizations/"+org+"/settings", testToken,
		map[string]any{"approvals_required": kinds}); rec.Code != http.StatusOK {
		t.Fatalf("setting approvals_required: %d %s", rec.Code, rec.Body.String())
	}
}

func TestAnErasureWaitsForASecondPerson(t *testing.T) {
	s, _ := newTestServer(t)
	subject := seedSubject(t, s, true)
	var org string
	if err := s.db.QueryRow(context.Background(), `SELECT org_id::text FROM core.users WHERE id = $1::uuid`,
		subject).Scan(&org); err != nil {
		t.Fatal(err)
	}
	requireApprovals(t, s, org, "subject_erasure")
	asker := approvalToken(t, s, org, "asker", ScopeSubjectsErase)
	reader := approvalToken(t, s, org, "reader", ScopeConfigRead)
	approver := approvalToken(t, s, org, "approver", ScopeSubjectsErase)
	erased := func() bool {
		var n int
		_ = s.db.QueryRow(context.Background(), `SELECT count(*) FROM core.audit_events
			WHERE event_type = 'admin.subject_erased' AND subject_id = $1::uuid`, subject).Scan(&n)
		return n > 0
	}

	rec := call(t, s, http.MethodPost, "/admin/subjects/"+subject+"/erase", asker,
		map[string]any{"confirm_subject_id": subject, "deactivate": true})
	out := decoded(t, rec)
	id, _ := out["approval_id"].(string)
	if rec.Code != http.StatusAccepted || id == "" || out["status"] != "pending" {
		t.Fatalf("an erasure where it waits answered %d %s", rec.Code, rec.Body.String())
	}
	if erased() {
		t.Fatal("the erasure was made before anybody approved it")
	}

	approve := func(token string) *httptest.ResponseRecorder {
		return call(t, s, http.MethodPost, "/admin/approvals/"+id+"/approve", token, nil)
	}
	if rec := approve(asker); rec.Code != http.StatusForbidden || decoded(t, rec)["error"] != "approval_by_requester" {
		t.Fatalf("the one who asked approving answered %d %s", rec.Code, rec.Body.String())
	}
	// Somebody who could not make the erasure themselves: the replay is theirs,
	// so it is refused, and the request is not used up.
	if rec := approve(reader); rec.Code != http.StatusForbidden || decoded(t, rec)["status"] != "pending" {
		t.Fatalf("an approver without subjects:erase answered %d %s", rec.Code, rec.Body.String())
	}
	if erased() {
		t.Fatal("an approver without the scope made the erasure")
	}
	rec = approve(approver)
	out = decoded(t, rec)
	if rec.Code != http.StatusOK || out["status"] != "approved" || out["result_status"] != float64(http.StatusOK) {
		t.Fatalf("a second person with the scope approving answered %d %s", rec.Code, rec.Body.String())
	}
	if !erased() {
		t.Fatal("approved, and no erasure was made")
	}
	if rec := approve(approver); rec.Code != http.StatusNotFound {
		t.Errorf("approving it a second time answered %d", rec.Code)
	}

	list := decoded(t, call(t, s, http.MethodGet, "/admin/organizations/"+org+"/approvals", testToken, nil))
	approvals, _ := list["approvals"].([]any)
	if len(approvals) != 1 || approvals[0].(map[string]any)["status"] != "approved" ||
		!strings.HasPrefix(approvals[0].(map[string]any)["decided_by"].(string), "approver-") {
		t.Errorf("the approvals read %v", list)
	}
}

// The org-owner role waits; any other grant does not. Relaxing the rule waits
// too, or one token could turn it off and then act alone; adding to it does not.
func TestAnOwnerGrantAndRelaxingTheRuleWait(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftMigrationOrg(t, s, false)
	requireApprovals(t, s, org, "owner_grant")
	// A grant may be no wider than its granter, so both hold what org-owner does.
	owner := approvalToken(t, s, org, "owner", Roles["org-owner"]...)
	second := approvalToken(t, s, org, "second", Roles["org-owner"]...)
	var person string
	if err := s.db.QueryRow(context.Background(), `INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, sha256(gen_random_uuid()::text::bytea) || sha256(gen_random_uuid()::text::bytea), $2)
		RETURNING id::text`, org, "grantee-"+org[:8]+"@example.test").Scan(&person); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, person) })
	bindings := "/admin/organizations/" + org + "/role-bindings"

	if rec := call(t, s, http.MethodPost, bindings, owner, map[string]any{"role": "auditor", "user_id": person}); rec.Code != http.StatusCreated {
		t.Fatalf("an auditor grant answered %d %s", rec.Code, rec.Body.String())
	}
	rec := call(t, s, http.MethodPost, bindings, owner, map[string]any{"role": "org-owner", "user_id": person})
	id, _ := decoded(t, rec)["approval_id"].(string)
	if rec.Code != http.StatusAccepted || id == "" {
		t.Fatalf("an org-owner grant answered %d %s", rec.Code, rec.Body.String())
	}
	rec = call(t, s, http.MethodPost, "/admin/approvals/"+id+"/approve", second, nil)
	if out := decoded(t, rec); rec.Code != http.StatusOK || out["result_status"] != float64(http.StatusCreated) {
		t.Fatalf("approving the grant answered %d %s", rec.Code, rec.Body.String())
	}
	var holds bool
	if err := s.db.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM core.admin_role_bindings
		WHERE org_id = $1::uuid AND user_id = $2::uuid AND role = 'org-owner')`, org, person).Scan(&holds); err != nil || !holds {
		t.Fatalf("approved, and the person holds org-owner: %v (%v)", holds, err)
	}

	settings := "/admin/organizations/" + org + "/settings"
	if rec := call(t, s, http.MethodPatch, settings, owner, map[string]any{"approvals_required": []string{"owner_grant",
		"subject_erasure"}}); rec.Code != http.StatusOK {
		t.Fatalf("adding to the rule answered %d %s", rec.Code, rec.Body.String())
	}
	rec = call(t, s, http.MethodPatch, settings, owner, map[string]any{"approvals_required": []string{}})
	id, _ = decoded(t, rec)["approval_id"].(string)
	if rec.Code != http.StatusAccepted || id == "" {
		t.Fatalf("taking the rule away answered %d %s", rec.Code, rec.Body.String())
	}
	got := decoded(t, call(t, s, http.MethodGet, settings, testToken, nil))["approvals_required"]
	if list, _ := got.([]any); len(list) != 2 {
		t.Fatalf("the rule was taken away before anybody approved: %v", got)
	}
	// Withdrawn by the one who asked.
	if rec := call(t, s, http.MethodPost, "/admin/approvals/"+id+"/reject", owner, nil); rec.Code != http.StatusOK {
		t.Fatalf("withdrawing answered %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodPost, "/admin/approvals/"+id+"/approve", second, nil); rec.Code != http.StatusNotFound {
		t.Errorf("approving a withdrawn request answered %d", rec.Code)
	}
}

// Turning down somebody else's request takes the scope it needs, or a token
// holding no right to erase anybody could stop every erasure; one past its
// expiry cannot be approved.
func TestWhoMayTurnARequestDownAndExpiry(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftMigrationOrg(t, s, false)
	requireApprovals(t, s, org, "owner_grant")
	owner := approvalToken(t, s, org, "owner", Roles["org-owner"]...)
	reader := approvalToken(t, s, org, "reader", ScopeConfigRead)
	second := approvalToken(t, s, org, "second", Roles["org-owner"]...)
	ask := func() string {
		t.Helper()
		var person string
		if err := s.db.QueryRow(context.Background(), `INSERT INTO core.users (org_id, user_handle, email)
			VALUES ($1::uuid, sha256(gen_random_uuid()::text::bytea) || sha256(gen_random_uuid()::text::bytea),
			        'p-' || gen_random_uuid() || '@example.test') RETURNING id::text`, org).Scan(&person); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, person) })
		rec := call(t, s, http.MethodPost, "/admin/organizations/"+org+"/role-bindings", owner,
			map[string]any{"role": "org-owner", "user_id": person})
		id, _ := decoded(t, rec)["approval_id"].(string)
		if id == "" {
			t.Fatalf("asking answered %d %s", rec.Code, rec.Body.String())
		}
		return id
	}
	id := ask()
	if rec := call(t, s, http.MethodPost, "/admin/approvals/"+id+"/reject", reader, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a token without the scope turning it down answered %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodPost, "/admin/approvals/"+id+"/reject", second, nil); rec.Code != http.StatusOK {
		t.Errorf("somebody with the scope turning it down answered %d %s", rec.Code, rec.Body.String())
	}

	id = ask()
	if _, err := s.db.Exec(context.Background(), `UPDATE core.admin_approvals SET expires_at = now() - interval '1 second'
		WHERE id = $1::uuid`, id); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, s, http.MethodPost, "/admin/approvals/"+id+"/approve", second, nil); rec.Code != http.StatusNotFound {
		t.Errorf("approving an expired request answered %d %s", rec.Code, rec.Body.String())
	}
	list := decoded(t, call(t, s, http.MethodGet, "/admin/organizations/"+org+"/approvals", testToken, nil))
	approvals, _ := list["approvals"].([]any)
	if len(approvals) != 2 || approvals[0].(map[string]any)["status"] != "expired" ||
		approvals[1].(map[string]any)["status"] != "rejected" {
		t.Errorf("the approvals read %v", list)
	}

	// Another organisation's token sees nothing of it.
	other := newDriftMigrationOrg(t, s, false)
	outsider := approvalToken(t, s, other, "outsider", Roles["org-owner"]...)
	if rec := call(t, s, http.MethodPost, "/admin/approvals/"+id+"/reject", outsider, nil); rec.Code != http.StatusForbidden {
		t.Errorf("another organisation's token answered %d", rec.Code)
	}
}
