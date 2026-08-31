package store

import (
	"fmt"
	"testing"
	"time"

	"signari.dev/engine/internal/scim"
)

// Scoping a provisioning target to one group's members.
//
// Provisioning is access: an account at a target IS the ability to sign in
// there. So "who does this target receive" is an authorisation question, and the
// answer used to be "everybody in the organisation".

// scimScopeFixture builds an org, two users, a group holding one of them, and a
// target. Returns the target and both user ids.
func scimScopeFixture(t *testing.T, scoped bool) (scim.Target, string, string) {
	t.Helper()
	ctx, orgID, inGroup := profileFixture(t)
	_, _, outsideGroup := profileFixture(t)
	conn := connect(t)
	stamp := time.Now().UnixNano()

	// Put the second user in the same org, so the only difference is membership.
	_, err := conn.Exec(ctx, `UPDATE core.users SET org_id = $1::uuid WHERE id = $2::uuid`,
		orgID, outsideGroup)
	must(t, err)

	var groupID string
	must(t, conn.QueryRow(ctx, `
		INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, $2, $2) RETURNING id::text`,
		orgID, fmt.Sprintf("scoped-%d", stamp)).Scan(&groupID))
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, `DELETE FROM core.groups WHERE id = $1::uuid`, groupID)
	})

	_, err = conn.Exec(ctx, `
		INSERT INTO core.group_members (group_id, user_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, groupID, inGroup, orgID)
	must(t, err)

	target := scim.Target{ID: fmt.Sprintf("%d", stamp), OrgID: orgID}
	// A real uuid for the target, since SCIMDesiredState casts it.
	must(t, conn.QueryRow(ctx, `
		INSERT INTO core.scim_targets (org_id, slug, display_name, base_url, token, kind)
		VALUES ($1::uuid, $2, 'T', 'https://t.test/scim/v2', 'x'::bytea, 'scim')
		RETURNING id::text`, orgID, fmt.Sprintf("tgt-%d", stamp)).Scan(&target.ID))
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, `DELETE FROM core.scim_targets WHERE id = $1::uuid`, target.ID)
	})

	if scoped {
		target.ScopeGroupID = groupID
	}
	return target, inGroup, outsideGroup
}

// An unscoped target still receives everybody, unchanged.
func TestAnUnscopedTargetReceivesEveryone(t *testing.T) {
	target, inGroup, outsideGroup := scimScopeFixture(t, false)
	conn := connect(t)

	desired, err := SCIMDesiredState(t.Context(), conn, target)
	must(t, err)

	active := map[string]bool{}
	for _, d := range desired {
		active[d.UserID] = d.Active
	}
	if !active[inGroup] || !active[outsideGroup] {
		t.Fatalf("an unscoped target did not receive both users (in=%v out=%v). "+
			"Every target behaved this way before scoping existed and must be "+
			"unchanged.", active[inGroup], active[outsideGroup])
	}
}

// A scoped target treats a non-member as INACTIVE, not as absent.
//
// The distinction is the whole feature. Filtering a non-member out entirely
// would leave a live account at the remote system for somebody who lost access
// — the exact failure reconciling from desired state is supposed to make
// impossible.
func TestAScopedTargetDeactivatesANonMemberRatherThanIgnoringThem(t *testing.T) {
	target, inGroup, outsideGroup := scimScopeFixture(t, true)
	conn := connect(t)
	ctx := t.Context()

	// The non-member already has an account there, which is the case that
	// matters: somebody who was provisioned and has since left the group.
	_, err := conn.Exec(ctx, `
		INSERT INTO core.scim_links (target_id, user_id, org_id, remote_id, last_synced_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'remote-1', now())`,
		target.ID, outsideGroup, target.OrgID)
	must(t, err)

	desired, err := SCIMDesiredState(ctx, conn, target)
	must(t, err)

	seen := map[string]bool{}
	active := map[string]bool{}
	for _, d := range desired {
		seen[d.UserID] = true
		active[d.UserID] = d.Active
	}

	if !seen[outsideGroup] {
		t.Fatal("a non-member with an existing account vanished from the desired " +
			"state. Nothing would then deactivate their remote account, leaving " +
			"a live login for somebody who lost access.")
	}
	if active[outsideGroup] {
		t.Error("a non-member is reported ACTIVE at a scoped target; their " +
			"account would stay alive")
	}
	if !active[inGroup] {
		t.Error("a member is reported inactive at a scoped target")
	}
}

// A non-member with no account is not provisioned at all.
func TestAScopedTargetDoesNotProvisionANonMember(t *testing.T) {
	target, _, outsideGroup := scimScopeFixture(t, true)
	conn := connect(t)

	desired, err := SCIMDesiredState(t.Context(), conn, target)
	must(t, err)

	for _, d := range desired {
		if d.UserID == outsideGroup && d.Active {
			t.Fatal("a non-member with no account was listed as active; the " +
				"target would create one for somebody outside its scope")
		}
	}
}
