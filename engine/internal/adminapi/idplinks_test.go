package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// newDriftLinkedUser is a person in an organisation of the test's own with an
// assertion issuer, and the person's links path for it; linked links the
// subject "drift-subject" to them first.
func newDriftLinkedUser(t *testing.T, s *Server, linked bool) (userID, slug, path string) {
	t.Helper()
	ctx := context.Background()
	org, slug, _ := newDriftIdP(t, s, "oidc")
	if err := s.db.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, sha256(gen_random_uuid()::text::bytea) || sha256(gen_random_uuid()::text::bytea), $2)
		RETURNING id::text`, org, "linked-"+org[:8]+"@example.test").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if linked {
		if _, err := store.LinkSubject(ctx, s.db, org, slug, userID, "drift-subject"); err != nil {
			t.Fatal(err)
		}
	}
	return userID, slug, "/admin/users/" + userID + "/identity-links/" + slug
}

// A person is linked to an upstream subject, the link read and removed,
// through the Admin API as `signari idp link` and `unlink` do it (6.07); a
// subject acting as somebody else is refused rather than moved (0.37), and
// what the jwt-bearer grant resolves follows each step.
func TestAnIdentityLinkIsMadeAndRemovedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID, slug, path := newDriftLinkedUser(t, s, false)
	var providerID, org string
	if err := s.db.QueryRow(ctx, `SELECT id::text, org_id::text FROM core.identity_providers WHERE slug = $1`, slug).
		Scan(&providerID, &org); err != nil {
		t.Fatal(err)
	}
	resolves := func(sub string) string {
		t.Helper()
		got, _, err := store.FindActiveFederatedUser(ctx, s.db, providerID, sub)
		if err != nil && !errors.Is(err, store.ErrNoLinkedAccount) && !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		return got
	}
	answer := func(method, p string, body any, want int) map[string]any {
		t.Helper()
		rec := call(t, s, method, p, testToken, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Errorf("%s %s %v answered %d, want %d: %s", method, p, body, rec.Code, want, rec.Body.String())
		}
		return out
	}

	if out := answer(http.MethodPut, path, map[string]any{"subject": " repo:acme/deploy "}, http.StatusOK); out["changed"] != true {
		t.Errorf("linking answered %v", out)
	}
	if got := resolves("repo:acme/deploy"); got != userID {
		t.Fatalf("after linking the subject resolves to %q, want %s", got, userID)
	}
	list := call(t, s, http.MethodGet, "/admin/users/"+userID+"/identity-links", testToken, nil)
	if !strings.Contains(list.Body.String(), `"provider":"`+slug+`"`) ||
		!strings.Contains(list.Body.String(), `"subject":"repo:acme/deploy"`) {
		t.Errorf("the links read %s", list.Body.String())
	}
	// The same link again changes nothing and moves no version.
	before := currentVersion(t, s)
	if out := answer(http.MethodPut, path, map[string]any{"subject": "repo:acme/deploy"}, http.StatusOK); out["changed"] != false {
		t.Errorf("linking again answered %v", out)
	}
	if after := currentVersion(t, s); after != before {
		t.Errorf("linking again moved the version from %d to %d", before, after)
	}

	// Another person cannot be given the subject by linking it again, and
	// this person cannot be given a second one.
	other, _, _ := newDriftLinkedUser(t, s, false)
	if _, err := s.db.Exec(ctx, `UPDATE core.users SET org_id = $1::uuid WHERE id = $2::uuid`, org, other); err != nil {
		t.Fatal(err)
	}
	if out := answer(http.MethodPut, "/admin/users/"+other+"/identity-links/"+slug,
		map[string]any{"subject": "repo:acme/deploy"}, http.StatusConflict); out["error"] != "link_taken" {
		t.Errorf("moving the subject answered %v", out)
	}
	if got := resolves("repo:acme/deploy"); got != userID {
		t.Errorf("after the refused move the subject resolves to %q, want %s", got, userID)
	}
	if out := answer(http.MethodPut, path, map[string]any{"subject": "repo:acme/other"}, http.StatusConflict); out["error"] != "link_taken" {
		t.Errorf("a second subject answered %v", out)
	}
	// A provider of another organisation is not this person's to link to.
	_, theirs, _ := newDriftIdP(t, s, "oidc")
	if out := answer(http.MethodPut, "/admin/users/"+userID+"/identity-links/"+theirs,
		map[string]any{"subject": "x"}, http.StatusNotFound); out["error"] != "provider_not_found" {
		t.Errorf("another organisation's provider answered %v", out)
	}
	if out := answer(http.MethodPut, path, map[string]any{"subject": "  "}, http.StatusBadRequest); out["error"] != "subject_required" {
		t.Errorf("no subject answered %v", out)
	}

	if out := answer(http.MethodDelete, path, nil, http.StatusOK); out["subject"] != "repo:acme/deploy" {
		t.Errorf("unlinking answered %v", out)
	}
	if got := resolves("repo:acme/deploy"); got != "" {
		t.Errorf("after unlinking the subject still resolves to %s", got)
	}
	if out := answer(http.MethodDelete, path, nil, http.StatusNotFound); out["error"] != "link_not_found" {
		t.Errorf("unlinking again answered %v", out)
	}
}

// A link lets whoever controls the subject mint tokens for the person, so a
// person who may impersonate is linked only with the privileged scope.
func TestLinkingAPrivilegedPersonNeedsThePrivilegedScope(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID, _, path := newDriftLinkedUser(t, s, false)
	var org string
	if err := s.db.QueryRow(ctx, `SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&org); err != nil {
		t.Fatal(err)
	}
	var group string
	if err := s.db.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name, may_impersonate)
		VALUES ($1::uuid, 'impersonators', 'Impersonators', true) RETURNING id::text`, org).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, group, userID, org); err != nil {
		t.Fatal(err)
	}
	plain := mintToken(t, s, "link-plain-"+org[:8], org, []string{ScopeUsersWrite}, nil)
	rec := call(t, s, http.MethodPut, path, plain, map[string]any{"subject": "repo:acme/deploy"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("users:write linking a person who may impersonate answered %d %s", rec.Code, rec.Body.String())
	}
	var n int
	_ = s.db.QueryRow(ctx, `SELECT count(*) FROM core.federated_identities WHERE user_id = $1::uuid`, userID).Scan(&n)
	if n != 0 {
		t.Error("the refused link was made")
	}
}
