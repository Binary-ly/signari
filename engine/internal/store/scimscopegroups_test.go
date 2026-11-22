package store

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// Several groups mean anybody in any of them (7.11), and leaving one of two is not
// leaving the target: an application two teams use took a third group kept by hand.
func TestATargetLimitedToSeveralGroupsTakesTheirMembers(t *testing.T) {
	target, first, second := scimScopeFixture(t, false)
	conn := connect(t)
	ctx := t.Context()
	var slug string
	must(t, conn.QueryRow(ctx, `SELECT slug FROM core.scim_targets WHERE id = $1::uuid`, target.ID).Scan(&slug))

	stamp := time.Now().UnixNano()
	group := func(name, member string) string {
		t.Helper()
		var id string
		must(t, conn.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name)
			VALUES ($1::uuid, $2, $2) RETURNING id::text`, target.OrgID, name).Scan(&id))
		_, err := conn.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
			VALUES ($1::uuid, $2::uuid, $3::uuid)`, id, member, target.OrgID)
		must(t, err)
		t.Cleanup(func() {
			_, _ = conn.Exec(ctx, `DELETE FROM core.scim_target_scope_groups WHERE group_id = $1::uuid`, id)
			_, _ = conn.Exec(ctx, `DELETE FROM core.groups WHERE id = $1::uuid`, id)
		})
		return id
	}
	teamA, teamB := fmt.Sprintf("team-a-%d", stamp), fmt.Sprintf("team-b-%d", stamp)
	group(teamA, first)
	idB := group(teamB, second)

	// As a sync reads them.
	active := func() map[string]bool {
		t.Helper()
		scoped := target
		must(t, conn.QueryRow(ctx, `SELECT ARRAY(SELECT group_id::text FROM core.scim_target_scope_groups
			WHERE target_id = $1::uuid)`, target.ID).Scan(&scoped.ScopeGroupIDs))
		desired, err := SCIMDesiredState(ctx, conn, scoped)
		must(t, err)
		out := map[string]bool{}
		for _, d := range desired {
			out[d.UserID] = d.Active
		}
		return out
	}

	must(t, SetSCIMTargetScope(ctx, conn, target.OrgID, slug, []string{teamA, teamB}))
	if got := active(); !got[first] || !got[second] {
		t.Errorf("limited to both groups: %v", got)
	}

	must(t, SetSCIMTargetScope(ctx, conn, target.OrgID, slug, []string{teamA}))
	if got := active(); !got[first] || got[second] {
		t.Errorf("limited to one: %v", got)
	}

	// Replaced, not added to, and a group named twice or blank is nothing.
	must(t, SetSCIMTargetScope(ctx, conn, target.OrgID, slug, []string{teamB, teamB, " "}))
	rows, err := SCIMTargets(ctx, conn, target.OrgID)
	must(t, err)
	for _, r := range rows {
		if r.Slug == slug && !slices.Equal(r.ScopeGroups, []string{teamB}) {
			t.Errorf("held %v", r.ScopeGroups)
		}
	}

	// An unknown name changes nothing and says which.
	err = SetSCIMTargetScope(ctx, conn, target.OrgID, slug, []string{teamA, "nobody-has-this"})
	if !errors.Is(err, ErrScopeGroupUnknown) || !strings.Contains(err.Error(), "nobody-has-this") {
		t.Errorf("answered %v", err)
	}
	if got := active(); got[first] || !got[second] {
		t.Errorf("a refused change moved the scope: %v", got)
	}
	if err := SetSCIMTargetScope(ctx, conn, target.OrgID, "no-such-target", nil); !errors.Is(err, ErrSCIMTargetUnknown) {
		t.Errorf("an unknown target answered %v", err)
	}

	// A group held here cannot go, as deleting it could widen the target.
	if _, err := conn.Exec(ctx, `DELETE FROM core.groups WHERE id = $1::uuid`, idB); err == nil {
		t.Error("a group a target is limited to was deleted")
	}

	// None is everybody, the same as never having been limited.
	must(t, SetSCIMTargetScope(ctx, conn, target.OrgID, slug, []string{}))
	if got := active(); !got[first] || !got[second] {
		t.Errorf("widened: %v", got)
	}
}
