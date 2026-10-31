package store

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Finding a person uses an index on the engine's own connection (0.52).
//
// Everything else in this suite connects as a role that bypasses row security,
// so a query that reads every person looks fine in every other test: under a
// policy PostgreSQL will not run a function that is not leakproof on a column
// first, `lower(email) = $1` can use no index at all, and every sign-in was a
// sequential scan. So this becomes the engine, with sequential scans priced
// out, which leaves a plan that uses the index only if one can be used.
func TestFindingSomebodyUsesAnIndexAsTheEngine(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, testDSN(t))
	must(t, err)
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if _, err := conn.Exec(ctx, "SET SESSION AUTHORIZATION signari_engine"); err != nil {
		t.Skipf("the test database's role cannot become the engine: %v", err)
	}
	_, err = conn.Exec(ctx, "SET enable_seqscan = off")
	must(t, err)

	// No organisation in these: how many people one holds decides which index is
	// cheapest, and what is being asked is whether this one can be used at all.
	for name, c := range map[string]struct{ query, index string }{
		"by address":  {`SELECT id FROM core.users WHERE email_fold = lower('A@example.test')`, "users_email_fold_idx"},
		"by username": {`SELECT id FROM core.users WHERE username_fold = lower('Alice')`, "users_username_fold_idx"},
		"by either": {`SELECT id FROM core.users u WHERE u.email_fold = lower('a') OR u.username_fold = lower('a')`,
			"users_username_fold_idx"},
		"by a prefix, across organisations": {`SELECT id FROM core.users
			WHERE email_fold ~>=~ lower('ali') AND email_fold ~<~ (lower('ali') || chr(1114111))`, "users_email_fold_idx"},
	} {
		rows, err := conn.Query(ctx, "EXPLAIN (COSTS OFF) "+c.query)
		must(t, err)
		lines, err := pgx.CollectRows(rows, pgx.RowTo[string])
		must(t, err)
		plan := strings.Join(lines, "\n")
		if !strings.Contains(plan, c.index) || strings.Contains(plan, "Seq Scan") {
			t.Errorf("%s does not use %s as the engine:\n%s", name, c.index, plan)
		}
	}
}
