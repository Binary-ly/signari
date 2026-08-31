package store

import (
	"fmt"
	"testing"
	"time"
)

// A directory may never be mapped onto a group that grants impersonation.
//
// `groups.may_impersonate` lets members act as other users. The admin API
// already refuses to set it, because a `groups:write` token could otherwise
// grant itself impersonation by flagging a group its operator belongs to.
//
// The reasoning is stronger here: the party choosing who is in the REMOTE group
// is whoever administers that directory, not this deployment. If an
// impersonation group could be synced, they could add themselves and act as
// anybody — a privilege escalation that crosses an organisational boundary and
// leaves no trace in this system's own configuration.
//
// Both directions are enforced, because one alone is a check somebody walks
// around: mapping onto an impersonation group is refused, and giving
// impersonation to a group that is already a sync target is refused too.

func directoryFixture(t *testing.T, orgID string) string {
	t.Helper()
	conn := connect(t)
	var id string
	// Columns taken from the live schema rather than guessed. The first version
	// invented `name`, `base_dn` and `url`; the real ones are slug/display_name
	// and the ldap_* prefix, and a failing fixture would have skipped every
	// assertion below while the suite reported nothing.
	must(t, conn.QueryRow(t.Context(), `
		INSERT INTO core.directory_sources
			(org_id, kind, slug, display_name, credentials_enc, ldap_url, ldap_base_dn)
		VALUES ($1::uuid, 'ldap', $2, 'Test directory', $3, 'ldaps://dir.test',
		        'dc=example,dc=test')
		RETURNING id::text`,
		orgID, fmt.Sprintf("dir-%d", time.Now().UnixNano()),
		[]byte("not-a-real-credential")).Scan(&id))
	t.Cleanup(func() {
		_, _ = conn.Exec(t.Context(),
			`DELETE FROM core.directory_sources WHERE id = $1::uuid`, id)
	})
	return id
}

func groupFixture(t *testing.T, orgID string, mayImpersonate bool) string {
	t.Helper()
	conn := connect(t)
	var id string
	must(t, conn.QueryRow(t.Context(), `
		INSERT INTO core.groups (org_id, name, display_name, may_impersonate)
		VALUES ($1::uuid, $2, $2, $3) RETURNING id::text`,
		orgID, fmt.Sprintf("grp-%d", time.Now().UnixNano()), mayImpersonate).Scan(&id))
	t.Cleanup(func() {
		_, _ = conn.Exec(t.Context(), `DELETE FROM core.groups WHERE id = $1::uuid`, id)
	})
	return id
}

func TestADirectoryCannotBeMappedOntoAnImpersonationGroup(t *testing.T) {
	ctx, orgID, _ := profileFixture(t)
	conn := connect(t)
	sourceID := directoryFixture(t, orgID)
	groupID := groupFixture(t, orgID, true)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO core.directory_group_map (source_id, org_id, remote_group, group_id)
		VALUES ($1::uuid, $2::uuid, 'Admins', $3::uuid)`, sourceID, orgID, groupID)
	if err == nil {
		t.Fatal("a directory was mapped onto a group that grants impersonation. " +
			"Whoever administers that directory could add themselves to the remote " +
			"group and act as any user in this deployment.")
	}
}

// The other direction: a sync target may not later be given impersonation.
func TestASyncedGroupCannotLaterBeGivenImpersonation(t *testing.T) {
	ctx, orgID, _ := profileFixture(t)
	conn := connect(t)
	sourceID := directoryFixture(t, orgID)
	groupID := groupFixture(t, orgID, false)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	// Mapping an ordinary group is fine.
	_, err = tx.Exec(ctx, `
		INSERT INTO core.directory_group_map (source_id, org_id, remote_group, group_id)
		VALUES ($1::uuid, $2::uuid, 'Engineering', $3::uuid)`, sourceID, orgID, groupID)
	must(t, err)

	// Flipping the flag afterwards must be refused, or the check above is one
	// somebody walks around in two steps.
	_, err = tx.Exec(ctx,
		`UPDATE core.groups SET may_impersonate = true WHERE id = $1::uuid`, groupID)
	if err == nil {
		t.Fatal("a directory sync target was given impersonation after the fact. " +
			"The refusal at mapping time is then a check that can be walked " +
			"around in two steps.")
	}
}

// An ordinary group maps fine, or the rule above is refusing everything.
func TestAnOrdinaryGroupCanBeMapped(t *testing.T) {
	ctx, orgID, _ := profileFixture(t)
	conn := connect(t)
	sourceID := directoryFixture(t, orgID)
	groupID := groupFixture(t, orgID, false)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO core.directory_group_map (source_id, org_id, remote_group, group_id)
		VALUES ($1::uuid, $2::uuid, 'Engineering', $3::uuid)`,
		sourceID, orgID, groupID); err != nil {
		t.Fatalf("an ordinary group could not be mapped: %v", err)
	}
}
