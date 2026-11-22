package directory

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// seedLinked puts n people of orgID, each linked to sourceID, straight into the tables, as a
// first sync of a large directory leaves them: just loaded, and analysed by nobody yet.
func seedLinked(t *testing.T, pool *pgxpool.Pool, orgID, sourceID string, n int) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		WITH made AS (
			INSERT INTO core.users (org_id, user_handle, email)
			SELECT $1::uuid, sha256(($1::text || i::text)::bytea), 'seed-' || i || '-' || $3 || '@example.test'
			  FROM generate_series(1, $2::int) i
			RETURNING id, email)
		INSERT INTO core.directory_links (source_id, user_id, org_id, remote_id, remote_email, remote_name)
		SELECT $4::uuid, id, $1::uuid, 'r-' || email, email, 'Seeded' FROM made`,
		orgID, n, rnd(t), sourceID); err != nil {
		t.Fatalf("seeding %d linked people: %v", n, err)
	}
}

// A sync started right after a large one reads what it has linked in time that grows with the
// directory, not with its square (E.27). As one join it was planned on statistics from before
// the large sync: 531 people and 2 links were expected, a nested loop chosen, and a second sync
// of 100,000 with nothing to do took 566 seconds where the first took 14. Seeded here as the
// first sync leaves them, with no ANALYZE between.
func TestASyncRightAfterALargeOneReadsWhatItLinkedInLinearTime(t *testing.T) {
	pool := testDB(t)
	orgID, sourceID := fixture(t, pool)
	const n = 20000
	seedLinked(t, pool, orgID, sourceID, n)

	start := time.Now()
	local, err := LoadLocal(context.Background(), pool, sourceID, orgID)
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	linked := 0
	for _, l := range local {
		if l.RemoteID != "" && l.Name == "Seeded" {
			linked++
		}
	}
	if linked != n {
		t.Fatalf("read %d of the %d people linked to the source, with their names", linked, n)
	}
	if took > 3*time.Second {
		t.Errorf("reading %d linked people right after they were loaded took %s; that is a plan "+
			"comparing each person with every link", n, took.Round(time.Millisecond))
	}
}

// A sync that brings in or changes many people has the tables it wrote analysed before it
// returns (E.27), so the next sync, and everything else, is planned for the directory as it
// now is and not as it was. PostgreSQL 17's documentation, 14.4.8: after bulk loading,
// running ANALYZE "is strongly recommended".
func TestALargeSyncLeavesWhatItWroteAnalysed(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	orgID, sourceID := fixture(t, pool)
	started := time.Now().Add(-time.Second)

	local, err := LoadLocal(ctx, pool, sourceID, orgID)
	if err != nil {
		t.Fatal(err)
	}
	plan := BuildPlan(people(rnd(t), 0, bulkAnalyseFloor+500), local, "report", 100)
	if err := Apply(ctx, pool, sourceID, orgID, plan); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"users", "directory_links"} {
		var at *time.Time
		if err := pool.QueryRow(ctx, `SELECT last_analyze FROM pg_stat_user_tables
			WHERE schemaname = 'core' AND relname = $1`, table).Scan(&at); err != nil {
			t.Fatal(err)
		}
		if at == nil || at.Before(started) {
			t.Errorf("core.%s was last analysed at %v, before a sync of %d people that began at %s",
				table, at, bulkAnalyseFloor+500, started.Format(time.RFC3339))
		}
	}
}
