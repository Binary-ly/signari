package directory

import (
	"context"
	"testing"
)

// A person a sync creates in an organisation migrating off a provider is
// pending on that source (2.01), so their first password sign-in is verified
// there; a disabled source, or none, leaves them as before. Nothing marked
// synced users pending, so delegated verification never applied to them.
func TestASyncedUserIsPendingOnAnEnabledMigrationSource(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	orgID, sourceID := fixture(t, pool)
	suffix := rnd(t)

	var migrationID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.migration_sources (org_id, kind, display_name, token_endpoint, bind_dn_template, enabled)
		VALUES ($1::uuid, 'ldap', 'old directory', 'ldaps://dir.example.test', 'uid={username},dc=example', false)
		RETURNING id::text`, orgID).Scan(&migrationID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM core.migration_sources WHERE id = $1::uuid`, migrationID)
	})

	sync := func(remote ...RemoteUser) {
		t.Helper()
		local, err := LoadLocal(ctx, pool, sourceID, orgID)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, pool, sourceID, orgID, BuildPlan(remote, local, "deactivate", 100)); err != nil {
			t.Fatal(err)
		}
	}
	state := func(email string) (st string, source *string) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT migration_state, migration_source_id::text FROM core.users
			WHERE org_id = $1::uuid AND email = $2`, orgID, email).Scan(&st, &source); err != nil {
			t.Fatal(err)
		}
		return
	}
	first := RemoteUser{ID: "m1", Email: "first-" + suffix + "@example.test", Name: "First"}
	second := RemoteUser{ID: "m2", Email: "second-" + suffix + "@example.test", Name: "Second"}

	sync(first)
	if st, src := state(first.Email); st != "none" || src != nil {
		t.Errorf("with the source disabled, a synced user is %q on %v; want none", st, src)
	}
	if _, err := pool.Exec(ctx, `UPDATE core.migration_sources SET enabled = true WHERE id = $1::uuid`, migrationID); err != nil {
		t.Fatal(err)
	}
	sync(first, second)
	if st, src := state(second.Email); st != "pending" || src == nil || *src != migrationID {
		t.Errorf("with the source enabled, a synced user is %q on %v; want pending on %s", st, src, migrationID)
	}
	if st, _ := state(first.Email); st != "none" {
		t.Errorf("a user already here became %q when the sync ran again", st)
	}
}
