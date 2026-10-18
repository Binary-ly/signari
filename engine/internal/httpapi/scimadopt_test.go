package httpapi

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A SCIM source manages the groups it created and no others. It once adopted
// any local group whose name its display name derived to, then replaced the
// members: an upstream that sent "support" took over a group that may
// impersonate, put its own users in it and removed the operator's.

// localGroup creates a group in the fixture's organisation that no source
// created, with one member who is not provisioned by any source.
func (f *scimFixture) localGroup(t *testing.T, name string, mayImpersonate bool) (groupID, memberID string) {
	t.Helper()
	ctx := context.Background()
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.groups (org_id, name, display_name, may_impersonate)
		VALUES ($1::uuid, $2, $2, $3) RETURNING id::text`,
		f.orgID, name, mayImpersonate).Scan(&groupID); err != nil {
		t.Fatalf("local group: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, sha256($2::bytea) || sha256($3::bytea), $4) RETURNING id::text`,
		f.orgID, fmt.Sprint(time.Now().UnixNano()), fmt.Sprint(time.Now().UnixNano()+1),
		fmt.Sprintf("local-%d@example.test", time.Now().UnixNano())).Scan(&memberID); err != nil {
		t.Fatalf("local member: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.group_members (group_id, user_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		groupID, memberID, f.orgID); err != nil {
		t.Fatalf("local membership: %v", err)
	}
	return groupID, memberID
}

func (f *scimFixture) postGroup(t *testing.T, displayName string, members ...string) (int, map[string]any) {
	t.Helper()
	list := make([]string, 0, len(members))
	for _, m := range members {
		list = append(list, fmt.Sprintf(`{"value":%q}`, m))
	}
	return f.do(t, http.MethodPost, "/scim/v2/Groups", fmt.Sprintf(
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
		  "externalId":%q,"displayName":%q,"members":[%s]}`,
		fmt.Sprintf("ext-%d", time.Now().UnixNano()), displayName, strings.Join(list, ",")))
}

func (f *scimFixture) members(t *testing.T, groupID string) map[string]bool {
	t.Helper()
	rows, err := f.pool.Query(context.Background(),
		`SELECT user_id::text FROM core.group_members WHERE group_id = $1::uuid`, groupID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out[id] = true
	}
	return out
}

func (f *scimFixture) userIDFor(t *testing.T, resourceID string) string {
	t.Helper()
	var id string
	if err := f.pool.QueryRow(context.Background(), `
		SELECT user_id::text FROM core.scim_source_links
		 WHERE source_id = $1::uuid AND resource_id::text = $2`, f.srcID, resourceID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestASCIMSourceCannotTakeOverALocalGroupByName(t *testing.T) {
	f := newSCIMFixture(t)
	upstreamUser := f.userIDFor(t, f.userA)

	for _, c := range []struct {
		name           string
		mayImpersonate bool
	}{
		{"support", true},
		{"engineering", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			groupID, local := f.localGroup(t, c.name, c.mayImpersonate)

			status, body := f.postGroup(t, c.name, f.userA)
			if status != http.StatusConflict {
				t.Fatalf("POST /Groups naming an existing local group gave %d %v, want 409", status, body)
			}
			got := f.members(t, groupID)
			if got[upstreamUser] {
				t.Fatal("the upstream's user was put in a group the upstream did not create")
			}
			if !got[local] {
				t.Fatal("the operator's member was removed by a source that does not own the group")
			}
			var links int
			if err := f.pool.QueryRow(context.Background(),
				`SELECT count(*) FROM core.scim_source_group_links WHERE group_id = $1::uuid`,
				groupID).Scan(&links); err != nil {
				t.Fatal(err)
			}
			if links != 0 {
				t.Fatal("the source was linked to a group it did not create")
			}
		})
	}

	// A name nobody holds is still the source's to create.
	if status, body := f.postGroup(t, "Fresh Group", f.userA); status != http.StatusCreated {
		t.Fatalf("a new group gave %d %v", status, body)
	}
}

// Nor can a second source in the same organisation take over the first one's.
func TestASecondSCIMSourceCannotTakeOverTheFirstsGroup(t *testing.T) {
	f := newSCIMFixture(t)
	f.createGroup(t, "Payroll", f.userA)

	second := *f
	second.token = f.token + "-second"
	sum := sha256.Sum256([]byte(second.token))
	if err := f.pool.QueryRow(context.Background(), `
		INSERT INTO core.scim_sources (org_id, slug, display_name, token_hash)
		VALUES ($1::uuid, 'second-source', 'Second', $2) RETURNING id::text`,
		f.orgID, sum[:]).Scan(&second.srcID); err != nil {
		t.Fatalf("second source: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.scim_sources WHERE id = $1::uuid`, second.srcID)
	})
	_, mallory := second.provisionUser(t, "mallory")

	if status, body := second.postGroup(t, "Payroll", mallory); status != http.StatusConflict {
		t.Fatalf("a second source naming the first one's group gave %d %v, want 409", status, body)
	}
}

// The other direction: a group a source manages cannot be given impersonation
// afterwards, or the refusal above is walked around by flipping the flag.
func TestAGroupASCIMSourceManagesCannotBeGivenImpersonation(t *testing.T) {
	f := newSCIMFixture(t)
	f.createGroup(t, "Helpdesk", f.userA)

	_, err := f.pool.Exec(context.Background(), `
		UPDATE core.groups SET may_impersonate = true
		 WHERE org_id = $1::uuid AND name = 'Helpdesk'`, f.orgID)
	if err == nil || !strings.Contains(err.Error(), "SCIM") {
		t.Fatalf("flagging a SCIM-managed group gave %v, want a refusal naming SCIM", err)
	}
}
