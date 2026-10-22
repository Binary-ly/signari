package adminapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// What PATCH /admin/users/{id} writes, GET /admin/users/{id} reads back
// (6.08). The read returned six fields, so a name set through the API, a
// password change asked for, or an address change clearing the verification
// could be written and never seen.
func TestAUserReadShowsWhatAPatchWrote(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	email := fmt.Sprintf("read-back-%d@example.test", time.Now().UnixNano())
	rec := call(t, s, http.MethodPost, "/admin/users", testToken, map[string]any{
		"org_id": anyOrgID(t, s), "email": email, "password": "rb-" + hex.EncodeToString(raw)})
	if rec.Code != http.StatusCreated {
		t.Fatalf("creating the user: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	t.Cleanup(func() { _, _ = s.db.Exec(ctx, `DELETE FROM core.users WHERE id = $1::uuid`, created.ID) })
	if _, err := s.db.Exec(ctx, `UPDATE core.users SET email_verified_at = now() WHERE id = $1::uuid`,
		created.ID); err != nil {
		t.Fatal(err)
	}

	read := func() userDetail {
		t.Helper()
		rec := call(t, s, http.MethodGet, "/admin/users/"+created.ID, testToken, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("reading the user: %d %s", rec.Code, rec.Body.String())
		}
		var u userDetail
		if err := json.Unmarshal(rec.Body.Bytes(), &u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	if u := read(); !u.EmailVerified || u.RequirePasswordChange || u.DisplayName != "" {
		t.Errorf("a new verified user read %+v", u)
	}

	rec = call(t, s, http.MethodPatch, "/admin/users/"+created.ID, testToken, map[string]any{
		"display_name": "Ada L", "given_name": "Ada", "surname": "Lovelace", "require_password_change": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("patching: %d %s", rec.Code, rec.Body.String())
	}
	u := read()
	if u.DisplayName != "Ada L" || u.GivenName != "Ada" || u.Surname != "Lovelace" || !u.RequirePasswordChange {
		t.Errorf("after the patch the read was %+v", u)
	}
	updated, err1 := time.Parse(time.RFC3339, u.UpdatedAt)
	createdAt, err2 := time.Parse(time.RFC3339, u.CreatedAt)
	if err1 != nil || err2 != nil || updated.Before(createdAt) {
		t.Errorf("updated_at %q, created_at %q", u.UpdatedAt, u.CreatedAt)
	}

	moved := "moved-" + email
	if rec := call(t, s, http.MethodPatch, "/admin/users/"+created.ID, testToken,
		map[string]any{"email": moved}); rec.Code != http.StatusOK {
		t.Fatalf("changing the address: %d %s", rec.Code, rec.Body.String())
	}
	if u := read(); u.Email != moved || u.EmailVerified {
		t.Errorf("after an address change the read was %+v; the verification belonged to the old address", u)
	}
}
