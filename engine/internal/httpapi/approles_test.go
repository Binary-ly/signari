package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// A role in an application, from the grant to what a relying party reads, and to a sign-in
// refused without it (11.10). A role is a relation on application:<client>, so a person
// holds one under whichever name it was granted to, or through a group, it ends when it
// expires, and it is read for each token, so taking one away takes it from the next.
func TestAPersonsRolesInAnApplicationReachItsTokens(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	n := time.Now().UnixNano()
	var email, username string
	if err := f.pool.QueryRow(ctx, `UPDATE core.users SET username = $2 WHERE id = $1::uuid
		RETURNING email, username`, f.userID, fmt.Sprintf("alice-%d", n)).Scan(&email, &username); err != nil {
		t.Fatal(err)
	}
	group := fmt.Sprintf("auditors-%d", n)
	var groupID string
	if err := f.pool.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, $2, 'Auditors') RETURNING id::text`, f.orgID, group).Scan(&groupID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, groupID, f.userID, f.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.pool.Exec(c, `DELETE FROM core.relations WHERE org_id = $1::uuid AND object_id = $2`, f.orgID, f.clientID)
		_, _ = f.pool.Exec(c, `DELETE FROM core.groups WHERE id = $1::uuid`, groupID)
		_, _ = f.pool.Exec(c, `UPDATE core.clients SET roles_claim = NULL WHERE client_id = $1`, f.clientID)
	})
	grant := func(subjectType, subject, role string) {
		t.Helper()
		if err := store.GrantRelation(ctx, f.pool, f.orgID, store.Relation{SubjectType: subjectType, SubjectID: subject,
			Relation: role, ObjectType: store.ApplicationObject, ObjectID: f.clientID}, ""); err != nil {
			t.Fatal(err)
		}
	}
	roles := func() []string {
		t.Helper()
		got, err := store.ApplicationRoles(ctx, f.pool, f.orgID, f.userID, f.clientID)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	if got := roles(); len(got) != 0 {
		t.Fatalf("somebody with no grant holds %v", got)
	}
	grant("user", strings.ToUpper(email), "by-address")
	grant("user", username, "by-username")
	grant("user", f.userID, "by-id")
	grant("group", group, "through-a-group")
	grant("user", "somebody-else@example.test", "not-mine")
	if err := store.GrantRelation(ctx, f.pool, f.orgID, store.Relation{SubjectType: "user", SubjectID: f.userID,
		Relation: "another-apps", ObjectType: store.ApplicationObject, ObjectID: "another-client"}, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.relations WHERE org_id = $1::uuid
			AND object_id = 'another-client'`, f.orgID)
	})
	want := []string{"by-address", "by-id", "by-username", "through-a-group"}
	if got := roles(); !slices.Equal(got, want) {
		t.Fatalf("roles %v, want %v", got, want)
	}
	past := time.Now().Add(-time.Hour)
	if err := store.GrantRelation(ctx, f.pool, f.orgID, store.Relation{SubjectType: "user", SubjectID: f.userID,
		Relation: "by-id", ObjectType: store.ApplicationObject, ObjectID: f.clientID, ExpiresAt: &past}, ""); err != nil {
		t.Fatal(err)
	}
	if got := roles(); slices.Contains(got, "by-id") {
		t.Errorf("an expired role is still held: %v", got)
	}

	redeem := func() map[string]any {
		t.Helper()
		verifier := strings.Repeat("a", 48)
		status, body := f.post(t, f.redeem(f.issueCodeWithScopes(t, verifier, []string{"openid"}), verifier))
		if status != http.StatusOK {
			t.Fatalf("redeeming a code: %d %v", status, body)
		}
		return body
	}
	claimsIn := func(raw string) map[string]any {
		t.Helper()
		b, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[1])
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Nothing is said until the client asks.
	body := redeem()
	if _, said := claimsIn(body["id_token"].(string))["app_roles"]; said {
		t.Error("a client that named no claim was told the roles")
	}

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	bad := "sub"
	if err := store.SetClientSettings(ctx, tx, f.clientID, store.ClientSettings{RolesClaim: &bad}); err == nil {
		t.Error("the roles were put in the claim that says who somebody is")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err = f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	name := "app_roles"
	if err := store.SetClientSettings(ctx, tx, f.clientID, store.ClientSettings{RolesClaim: &name}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	want = []string{"by-address", "by-username", "through-a-group"}
	asList := func(v any) []string {
		var out []string
		for _, s := range v.([]any) {
			out = append(out, s.(string))
		}
		return out
	}
	body = redeem()
	access := body["access_token"].(string)
	for where, raw := range map[string]string{"ID token": body["id_token"].(string), "access token": access} {
		got, said := claimsIn(raw)["app_roles"]
		if !said {
			t.Fatalf("the %s carries no roles", where)
		}
		if !slices.Equal(asList(got), want) {
			t.Errorf("the %s says %v, want %v", where, got, want)
		}
	}
	userinfo := func() map[string]any {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, oidc.PathUserinfo, nil)
		r.Header.Set("Authorization", "Bearer "+access)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusOK {
			t.Fatalf("userinfo: %d %s", rec.Code, rec.Body)
		}
		return out
	}
	if got, said := userinfo()["app_roles"]; !said || !slices.Equal(asList(got), want) {
		t.Errorf("userinfo says %v", got)
	}

	// Required at the door, and gone with the role.
	applyPolicy(t, f.srv, f.pool, f.orgID, fmt.Sprintf(`
version: 1
policies:
  - name: staff-only
    when: {client: %q}
    require:
      application_roles: [by-username]
tests:
  - {name: with it, given: {client: %q, application_roles: [by-username]}, expect: allow}
  - {name: without, given: {client: %q}, expect: deny}
`, f.clientID, f.clientID, f.clientID))
	decide := func() bool {
		t.Helper()
		d := f.srv.checkAccessPolicyUnobserved(ctx, f.orgID, f.clientID, f.userID, "openid", false, nil)
		return d == nil || d.Allowed
	}
	if !decide() {
		t.Fatal("somebody holding the role was refused")
	}
	if _, err := store.RevokeRelation(ctx, f.pool, f.orgID, store.Relation{SubjectType: "user", SubjectID: username,
		Relation: "by-username", ObjectType: store.ApplicationObject, ObjectID: f.clientID}); err != nil {
		t.Fatal(err)
	}
	if decide() {
		t.Error("somebody without the role was let in")
	}
	if got := asList(claimsIn(redeemAfterPolicy(t, f)["id_token"].(string))["app_roles"]); slices.Contains(got, "by-username") {
		t.Errorf("a role taken away is still in the next token: %v", got)
	}
}

// redeemAfterPolicy takes the policy back out of the way to read the next token.
func redeemAfterPolicy(t *testing.T, f *tokenFixture) map[string]any {
	t.Helper()
	removePolicy(t, f.srv, f.pool, f.orgID)
	verifier := strings.Repeat("a", 48)
	status, body := f.post(t, f.redeem(f.issueCodeWithScopes(t, verifier, []string{"openid"}), verifier))
	if status != http.StatusOK {
		t.Fatalf("redeeming a code: %d %v", status, body)
	}
	return body
}
