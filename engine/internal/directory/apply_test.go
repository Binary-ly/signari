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
