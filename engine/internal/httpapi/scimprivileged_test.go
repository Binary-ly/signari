package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// A SCIM source does not adopt a person who may act as others, does not
// re-address one, and its delete deactivates rather than removes one. It
// adopted any local account by address, administrators included, and could
// then PUT a new address onto it: a password reset away from an account that
// may impersonate anybody.
func TestASCIMSourceNeverAdoptsOrRewritesAPrivilegedPerson(t *testing.T) {
	f := newSCIMFixture(t)
	ctx := context.Background()
	groupID, adminID := f.localGroup(t, fmt.Sprintf("admins-%d", time.Now().UnixNano()), true)
	email := func(userID string) string {
		t.Helper()
		var e string
		if err := f.pool.QueryRow(ctx, `SELECT email FROM core.users WHERE id = $1::uuid`, userID).Scan(&e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := f.pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	adminEmail := email(adminID)

	ext := fmt.Sprintf("ext-admin-%d", time.Now().UnixNano())
	status, body := f.do(t, http.MethodPost, "/scim/v2/Users", fmt.Sprintf(
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		  "externalId":%q,"userName":%q,"active":true,
		  "emails":[{"value":%q,"primary":true}]}`, ext, "u-"+ext, adminEmail))
	if status != http.StatusForbidden {
		t.Fatalf("POST /Users naming an administrator's address answered %d %v, want 403", status, body)
	}
	if n := count(`SELECT count(*) FROM core.scim_source_links WHERE user_id = $1::uuid`, adminID); n != 0 {
		t.Fatal("the source adopted an administrator by address")
	}

	// A provisioned person who later came to administer.
	userA := f.userIDFor(t, f.userA)
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.group_members (group_id, user_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		groupID, userA, f.orgID); err != nil {
		t.Fatal(err)
	}
	before := email(userA)
	status, body = f.do(t, http.MethodPut, "/scim/v2/Users/"+f.userA, fmt.Sprintf(
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		  "externalId":%q,"userName":%q,"active":true,
		  "emails":[{"value":"attacker-%d@elsewhere.test","primary":true}]}`,
		"ext-"+f.nameA, f.nameA, time.Now().UnixNano()))
	if status != http.StatusForbidden || email(userA) != before {
		t.Fatalf("PUT re-addressing an administrator answered %d %v and left %q", status, body, email(userA))
	}
	status, body = f.do(t, http.MethodPatch, "/scim/v2/Users/"+f.userA,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		  "Operations":[{"op":"replace","path":"emails","value":[{"value":"b@elsewhere.test","primary":true}]}]}`)
	if status != http.StatusForbidden || email(userA) != before {
		t.Fatalf("PATCH re-addressing an administrator answered %d %v and left %q", status, body, email(userA))
	}
	// The same address resent is not a rewrite, and switching them off is
	// what offboarding needs.
	status, body = f.do(t, http.MethodPut, "/scim/v2/Users/"+f.userA, fmt.Sprintf(
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		  "externalId":%q,"userName":%q,"active":false,
		  "emails":[{"value":%q,"primary":true}]}`, "ext-"+f.nameA, f.nameA, before))
	if status != http.StatusOK {
		t.Fatalf("PUT deactivating an administrator at the same address answered %d %v", status, body)
	}

	if _, err := f.pool.Exec(ctx, `UPDATE core.scim_sources SET on_delete = 'delete' WHERE id = $1::uuid`,
		f.srcID); err != nil {
		t.Fatal(err)
	}
	if status, body = f.do(t, http.MethodDelete, "/scim/v2/Users/"+f.userA, ""); status != http.StatusNoContent {
		t.Fatalf("DELETE of an administrator answered %d %v, want 204", status, body)
	}
	if n := count(`SELECT count(*) FROM core.users WHERE id = $1::uuid AND status = 'deactivated'`, userA); n != 1 {
		t.Fatal("a delete under the delete policy removed an administrator instead of deactivating them")
	}
	if n := count(`SELECT count(*) FROM core.audit_events
	                WHERE event_type = 'scim.privileged_kept' AND subject_id = $1::uuid`, userA); n != 1 {
		t.Errorf("keeping the administrator left %d audit records, want 1", n)
	}

	// An ordinary person is still deleted under that policy.
	userB := f.userIDFor(t, f.userB)
	if status, _ = f.do(t, http.MethodDelete, "/scim/v2/Users/"+f.userB, ""); status != http.StatusNoContent {
		t.Fatalf("DELETE of an ordinary person answered %d", status)
	}
	if n := count(`SELECT count(*) FROM core.users WHERE id = $1::uuid`, userB); n != 0 {
		t.Fatal("an ordinary person was not deleted under the delete policy")
	}
}
