package directory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func rnd(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// fixture makes an organisation with a directory source and some users.
func fixture(t *testing.T, pool *pgxpool.Pool) (orgID, sourceID string) {
	t.Helper()
	ctx := context.Background()
	suffix := rnd(t)

	if err := pool.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, $1, $1 FROM core.instances ORDER BY created_at LIMIT 1
		RETURNING id::text`, "dirtest-"+suffix).Scan(&orgID); err != nil {
		t.Fatalf("creating an organisation: %v", err)
	}

	if err := pool.QueryRow(ctx, `
		INSERT INTO core.directory_sources (org_id, kind, slug, display_name,
		                                    credentials_enc, on_missing, dry_run)
		VALUES ($1::uuid, 'google', $2, 'test', '\x00'::bytea, 'deactivate', false)
		RETURNING id::text`, orgID, "src-"+suffix).Scan(&sourceID); err != nil {
		t.Fatalf("creating a source: %v", err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM core.users WHERE org_id = $1::uuid`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM core.organizations WHERE id = $1::uuid`, orgID)
	})
	return orgID, sourceID
}

// TestApplyCreatesLinksAndDeactivates walks a full reconciliation against the
// real schema: create somebody, then remove them upstream and watch them go.
func TestApplyCreatesLinksAndDeactivates(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	orgID, sourceID := fixture(t, pool)
	suffix := rnd(t)

	remote := []RemoteUser{
		{ID: "g1", Email: "alice-" + suffix + "@example.test", Name: "Alice"},
		{ID: "g2", Email: "bob-" + suffix + "@example.test", Name: "Bob"},
	}

	local, err := LoadLocal(ctx, pool, sourceID, orgID)
	if err != nil {
		t.Fatal(err)
	}
	plan := BuildPlan(remote, local, "deactivate", 20)
	if !plan.Safe() {
		t.Fatalf("the first sync was refused: %s", plan.Refused)
	}
	if err := Apply(ctx, pool, sourceID, orgID, plan); err != nil {
		t.Fatal(err)
	}

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM core.users WHERE org_id=$1::uuid AND status='active'`,
		orgID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("created %d users, want 2", n)
	}
	// The link is what makes the SECOND sync an update rather than a duplicate.
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM core.directory_links WHERE source_id=$1::uuid`,
		sourceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("recorded %d links, want 2", n)
	}

	// Run it again unchanged: nothing should happen. A reconciler that creates
	// duplicates on a repeat run is worse than useless.
	local, _ = LoadLocal(ctx, pool, sourceID, orgID)
	plan = BuildPlan(remote, local, "deactivate", 20)
	create, update, deactivate, _ := plan.Counts()
	if create+update+deactivate != 0 {
		t.Errorf("an unchanged re-sync proposed create=%d update=%d deactivate=%d",
			create, update, deactivate)
	}

	// Bob is signed in when he leaves.
	//
	// This one line is the difference between a test that passes and a test that
	// finds the bug. Without a session, the UPDATE that revokes sessions matches
	// zero rows and its values are never checked against the column's
	// constraint -- so a deactivation that could never work in production
	// passed here for as long as nobody was logged in.
	var bobID string
	if err := pool.QueryRow(ctx,
		`SELECT id::text FROM core.users WHERE org_id=$1::uuid AND email=$2`,
		orgID, remote[1].Email).Scan(&bobID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.sessions (sid, org_id, user_id, acr, amr, auth_time,
		                           not_after, cookie_hash)
		VALUES ($1, $2::uuid, $3::uuid, '1', ARRAY['pwd'], now(),
		        now() + interval '12 hours', sha256($4::bytea))`,
		"dir-test-"+suffix, orgID, bobID, []byte("cookie-"+suffix)); err != nil {
		t.Fatal(err)
	}
	// In an application that has to be told he left.
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, backchannel_logout_uri)
		VALUES ($1, $2::uuid, 'RP', 'public', 'https://rp.example.test/backchannel')`,
		"dir-rp-"+suffix, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core.session_clients (sid, client_id) VALUES ($1, $2)`,
		"dir-test-"+suffix, "dir-rp-"+suffix); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM core.outbox WHERE topic = 'backchannel_logout' AND payload->>'sub' = $1`, bobID)
	})

	// Now Bob leaves.
	local, _ = LoadLocal(ctx, pool, sourceID, orgID)
	plan = BuildPlan(remote[:1], local, "deactivate", 60)
	if !plan.Safe() {
		t.Fatalf("removing one of two was refused: %s", plan.Refused)
	}
	if err := Apply(ctx, pool, sourceID, orgID, plan); err != nil {
		t.Fatal(err)
	}

	var status string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM core.users WHERE org_id=$1::uuid AND email=$2`,
		orgID, remote[1].Email).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "deactivated" {
		t.Errorf("the departed user is %q, want deactivated", status)
	}
	// And his session is gone. A deactivated account with a live session is
	// still a signed-in person.
	var live int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM core.sessions WHERE user_id=$1::uuid AND revoked_at IS NULL`,
		bobID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Errorf("the departed user still has %d live session(s)", live)
	}
	// And the application he was signed in to is told. Ending the row alone
	// leaves him signed in there.
	var notices int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM core.outbox WHERE topic = 'backchannel_logout'
		   AND payload->>'sub' = $1 AND payload->>'client_id' = $2
		   AND payload->>'reason' = 'user_deactivated'`, bobID, "dir-rp-"+suffix).Scan(&notices); err != nil {
		t.Fatal(err)
	}
	if notices != 1 {
		t.Errorf("%d back-channel logout notices queued for the departed user's application, want 1", notices)
	}
	// And Alice is untouched.
	if err := pool.QueryRow(ctx,
		`SELECT status FROM core.users WHERE org_id=$1::uuid AND email=$2`,
		orgID, remote[0].Email).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Errorf("a user still in the directory became %q", status)
	}
}

// TestApplyRefusesAnUnsafePlan. The ceiling is enforced HERE as well as in the
// caller, because this is the function that does the damage.
func TestApplyRefusesAnUnsafePlan(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	orgID, sourceID := fixture(t, pool)

	unsafe := &Plan{
		Actions: []Action{{Kind: "deactivate", UserID: "00000000-0000-0000-0000-000000000000"}},
		Refused: "test refusal",
	}
	if err := Apply(ctx, pool, sourceID, orgID, unsafe); err == nil {
		t.Fatal("an unsafe plan was applied")
	}
}

// A directory entry sharing an administrator's address does not adopt them, and
// a linked person who later came to administer is not re-addressed by the
// directory. Deactivating them still goes through: a departed administrator
// must stop getting in.
func TestApplyNeverAdoptsOrReaddressesAPrivilegedPerson(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	orgID, sourceID := fixture(t, pool)
	suffix := rnd(t)

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	var groupID, adminID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.groups (org_id, name, display_name, may_impersonate)
		VALUES ($1::uuid, $2, 'Admins', true) RETURNING id::text`, orgID, "admins-"+suffix).Scan(&groupID); err != nil {
		t.Fatal(err)
	}
	adminEmail := "admin-" + suffix + "@example.test"
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, status, user_handle)
		VALUES ($1::uuid, $2, 'active', decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		        md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'))
		RETURNING id::text`, orgID, adminEmail).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO core.group_members (group_id, user_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		groupID, adminID, orgID)

	sync := func(remote []RemoteUser) {
		t.Helper()
		local, err := LoadLocal(ctx, pool, sourceID, orgID)
		if err != nil {
			t.Fatal(err)
		}
		plan := BuildPlan(remote, local, "deactivate", 100)
		if err := Apply(ctx, pool, sourceID, orgID, plan); err != nil {
			t.Fatal(err)
		}
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	plainEmail := "plain-" + suffix + "@example.test"
	sync([]RemoteUser{
		{ID: "g-admin", Email: adminEmail, Name: "Admin"},
		{ID: "g-plain", Email: plainEmail, Name: "Plain"},
	})
	if n := count(`SELECT count(*) FROM core.directory_links WHERE source_id = $1::uuid AND user_id = $2::uuid`,
		sourceID, adminID); n != 0 {
		t.Fatal("the directory adopted an administrator by address")
	}
	if n := count(`SELECT count(*) FROM core.audit_events
	                WHERE event_type = 'directory.privileged_skipped' AND subject_id = $1::uuid`, adminID); n != 1 {
		t.Errorf("the skipped adoption left %d audit records, want 1", n)
	}
	var plainID string
	if err := pool.QueryRow(ctx, `SELECT user_id::text FROM core.directory_links
	                               WHERE source_id = $1::uuid AND remote_id = 'g-plain'`, sourceID).Scan(&plainID); err != nil {
		t.Fatalf("an ordinary person was not provisioned alongside: %v", err)
	}

	exec(`INSERT INTO core.group_members (group_id, user_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		groupID, plainID, orgID)
	sync([]RemoteUser{
		{ID: "g-admin", Email: adminEmail, Name: "Admin"},
		{ID: "g-plain", Email: "moved-" + suffix + "@elsewhere.test", Name: "Plain"},
	})
	if n := count(`SELECT count(*) FROM core.users WHERE id = $1::uuid AND email = $2`, plainID, plainEmail); n != 1 {
		t.Fatal("the directory re-addressed a person who now administers")
	}

	sync([]RemoteUser{{ID: "g-admin", Email: adminEmail, Name: "Admin"}})
	if n := count(`SELECT count(*) FROM core.users WHERE id = $1::uuid AND status = 'deactivated'`, plainID); n != 1 {
		t.Fatal("an administrator removed upstream was not deactivated")
	}
}
