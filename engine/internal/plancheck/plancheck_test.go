package plancheck

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The plans the guards read, as PostgreSQL writes them, so that a change in what
// counts as reading a table whole is a change somebody made.
func TestReadWholeTellsASeekFromAWalk(t *testing.T) {
	for name, tc := range map[string]struct {
		plan string
		want []string
	}{
		"a sequential scan": {`Seq Scan on sessions  (cost=1.00 rows=1 width=4)
  Filter: (revoked_at < now())`, []string{"sessions"}},
		"a seek": {`Index Scan using sessions_pkey on sessions  (cost=0.28 rows=1 width=4)
  Index Cond: (sid = 'x'::text)
  Filter: (revoked_at IS NULL)`, nil},
		"an index walked and filtered": {`Index Scan using sessions_pkey on sessions  (cost=0.28 rows=1 width=4)
  Filter: (revoked_at < now())`, []string{"sessions"}},
		"an index walked backwards for one row": {`Limit  (cost=0.28 rows=1 width=4)
  ->  Index Scan Backward using audit_events_pkey on audit_events  (cost=0.28 rows=1 width=4)`, nil},
		"a bitmap": {`Bitmap Heap Scan on families  (cost=1.00 rows=1 width=4)
  Recheck Cond: (revoked_at < now())
  ->  Bitmap Index Scan on families_ended_idx  (cost=0.00 rows=1 width=0)
        Index Cond: (revoked_at < now())`, nil},
		"the filter of the next scan is not this one's": {`Nested Loop  (cost=0.28 rows=1 width=4)
  ->  Index Scan using a_pkey on a  (cost=0.28 rows=1 width=4)
        Index Cond: (id = 1)
  ->  Index Scan using b_a on b  (cost=0.28 rows=1 width=4)
        Filter: (x = 1)`, []string{"b"}},
	} {
		if got := ReadWhole(tc.plan); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: read %v, want %v", name, got, tc.want)
		}
	}
}

// With sorting left on in the seek-only pass, a statement no index can seek is still
// reported, on a table other tests have emptied as on any other, and one with an index
// made for it is not.
//
// Sorting was turned off there too until 3 November 2026, and on the shared database,
// emptied, admin reads of credential requests and issuer aliases were reported though
// an index served each: the seek cost as much as walking another index in order and
// filtering, and the walk won. That tie is not reproduced here, where the planner
// seeks either way; listplans_test.go in adminapi went red with the old setting and
// green with this one against the database that showed it.
func TestAnEmptiedTableDoesNotHideTheIndexMadeForAStatement(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set; skipping database-backed tests")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	schema := fmt.Sprintf("plancheck_%d", time.Now().UnixNano())
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE") })
	// Rows written and deleted, then analysed: no live row and some dead ones, as the
	// shared tables are between packages.
	for _, sql := range []string{
		"CREATE SCHEMA " + schema,
		"CREATE TABLE " + schema + ".requests (id uuid PRIMARY KEY, org uuid NOT NULL, other int, created_at timestamptz NOT NULL)",
		"CREATE INDEX requests_age ON " + schema + ".requests (created_at)",
		"CREATE INDEX requests_org ON " + schema + ".requests (org, created_at)",
		"INSERT INTO " + schema + ".requests SELECT gen_random_uuid(), gen_random_uuid(), n, now() FROM generate_series(1, 50) n",
		"DELETE FROM " + schema + ".requests",
		"ANALYZE " + schema + ".requests",
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	for name, tc := range map[string]struct {
		sql  string
		want []string
	}{
		"one organisation's, oldest first":     {"SELECT id FROM " + schema + ".requests WHERE org = $1 ORDER BY created_at", nil},
		"by a column no index holds":           {"SELECT id FROM " + schema + ".requests WHERE other = $1 ORDER BY created_at", []string{"requests"}},
		"by a column no index holds, unsorted": {"SELECT id FROM " + schema + ".requests WHERE other = $1", []string{"requests"}},
	} {
		arg := any("00000000-0000-0000-0000-000000000001")
		if tc.want != nil {
			arg = 7
		}
		plan, err := explain(ctx, pool, Statement{SQL: tc.sql, Args: []any{arg}}, seeksOnly)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := ReadWhole(plan); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: read %v whole, want %v\n%s", name, got, tc.want, plan)
		}
	}
}
