package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"signari.dev/engine/internal/store"
)

// What was issued, who holds it, and taking it back: one organisation's and no other's.
func TestACredentialIsRevokedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	person := newDriftUserIn(t, s, org)
	elsewhere := newDriftMigrationOrg(t, s, false)
	stranger := newDriftUserIn(t, s, elsewhere)
	issue := func(orgID, userID string) string {
		t.Helper()
		tx, err := s.db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		listID, index, err := store.AllocateCredentialStatus(ctx, tx, orgID, userID, "drift", nil)
		if err != nil {
			t.Fatal(err)
		}
		var id string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM core.issued_credentials WHERE list_id = $1::uuid AND idx = $2`,
			listID, index).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return id
	}
	first, second := issue(org, person), issue(org, person)
	theirs := issue(elsewhere, stranger)

	type page struct {
		Credentials []issuedCredentialView `json:"credentials"`
		NextCursor  string                 `json:"next_cursor"`
	}
	list := func(query string) page {
		t.Helper()
		rec := call(t, s, http.MethodGet, "/admin/organizations/"+org+"/issued-credentials"+query, testToken, nil)
		var out page
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("listing %q: %d %s", query, rec.Code, rec.Body)
		}
		return out
	}
	if got := list(""); len(got.Credentials) != 2 {
		t.Fatalf("listed %+v", got)
	}
	if got := list("?user_id=" + stranger); len(got.Credentials) != 0 {
		t.Errorf("another organisation's person listed %+v", got)
	}
	one := list("?limit=1")
	rest := list("?limit=1&cursor=" + one.NextCursor)
	if len(one.Credentials) != 1 || len(rest.Credentials) != 1 || one.Credentials[0].ID == rest.Credentials[0].ID ||
		rest.NextCursor != "" {
		t.Errorf("two pages of one: %+v, %+v", one, rest)
	}
	if rec := call(t, s, http.MethodGet, "/admin/organizations/"+org+"/issued-credentials?cursor=nope", testToken, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("a made-up cursor answered %d", rec.Code)
	}
	if rec := call(t, s, http.MethodGet, "/admin/organizations/"+org+"/issued-credentials?user_id=nope", testToken, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("a made-up user answered %d", rec.Code)
	}

	revoke := func(body map[string]any) (int, int64) {
		t.Helper()
		rec := call(t, s, http.MethodPost, "/admin/organizations/"+org+"/credential-revocations", testToken, body)
		var out struct {
			Revoked int64 `json:"revoked"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out.Revoked
	}
	for name, body := range map[string]map[string]any{
		"nothing":   {},
		"both":      {"credential_id": first, "user_id": person},
		"not an id": {"user_id": "nope"},
	} {
		if code, _ := revoke(body); code != http.StatusBadRequest {
			t.Errorf("%s answered %d", name, code)
		}
	}
	if code, _ := revoke(map[string]any{"credential_id": theirs}); code != http.StatusNotFound {
		t.Errorf("another organisation's credential answered %d", code)
	}
	if code, n := revoke(map[string]any{"user_id": stranger}); code != http.StatusOK || n != 0 {
		t.Errorf("another organisation's person answered %d, %d revoked", code, n)
	}
	if code, n := revoke(map[string]any{"credential_id": first}); code != http.StatusOK || n != 1 {
		t.Errorf("revoking one answered %d, %d revoked", code, n)
	}
	if code, n := revoke(map[string]any{"credential_id": first}); code != http.StatusOK || n != 0 {
		t.Errorf("revoking it again answered %d, %d revoked", code, n)
	}
	if code, n := revoke(map[string]any{"user_id": person}); code != http.StatusOK || n != 1 {
		t.Errorf("revoking the person's answered %d, %d revoked", code, n)
	}
	for _, c := range list("").Credentials {
		if c.RevokedAt == nil {
			t.Errorf("%s (the second was %s) still stands", c.ID, second)
		}
	}
	var untouched bool
	if err := s.db.QueryRow(ctx, `SELECT revoked_at IS NULL FROM core.issued_credentials WHERE id = $1::uuid`, theirs).Scan(&untouched); err != nil {
		t.Fatal(err)
	}
	if !untouched {
		t.Error("another organisation's credential was revoked")
	}

	tenant := mintToken(t, s, fmt.Sprintf("revoke-tenant-%s", elsewhere), elsewhere, []string{ScopeOrganizationsWrite, ScopeConfigRead}, nil)
	rec := call(t, s, http.MethodPost, "/admin/organizations/"+org+"/credential-revocations", tenant, map[string]any{"user_id": person})
	if rec.Code != http.StatusForbidden {
		t.Errorf("an organisation's token reached into another: %d", rec.Code)
	}
}
