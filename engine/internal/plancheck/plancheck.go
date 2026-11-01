// Package plancheck asks the planner whether statements a test watched being sent
// could find their rows without reading a table from end to end.
//
// A test's tables are small, so a statement with nothing under it is as fast there
// as one with an index, and the difference only exists at a size no test reaches.
// The plan does not depend on the size in the way the clock does: with every
// alternative made as unattractive as it can be, a plan still reading a whole table
// is one no index can serve. Used by tests alone.
package plancheck

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Statement is one thing sent to the database.
type Statement struct {
	SQL  string
	Args []any
}

// Recorder is a pgx.QueryTracer keeping what a pool sends.
type Recorder struct {
	mu   sync.Mutex
	sent []Statement
}

// TraceQueryStart keeps the statement.
func (r *Recorder) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, Statement{d.SQL, d.Args})
	return ctx
}

// TraceQueryEnd does nothing.
func (r *Recorder) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// Take answers what was sent since the last time, and starts again.
func (r *Recorder) Take() []Statement {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.sent
	r.sent = nil
	return out
}

var scanOf = regexp.MustCompile(`(?:Seq Scan on (\w+)|Index (?:Only )?Scan(?: Backward)? using \w+ on (\w+))`)

// ReadWhole names the tables a plan goes through from end to end. A sequential scan
// does, and so does an index walked with nothing to seek by and a filter throwing
// rows away, which is what the planner answers with when told not to do the first.
// An index walked with no filter is an ORDER BY ... LIMIT, and stops.
//
// A bitmap over a partial index with no condition reads that index whole and is not
// counted: on an empty table the planner picks one beside a primary key it could have
// sought, so counting it reports statements that are fine. One arm of an OR left to
// such an index is the gap this leaves, and refresh_token_families_live_age_idx,
// which is why that index was measured on a filled table and not found here.
func ReadWhole(plan string) []string {
	lines := strings.Split(plan, "\n")
	var out []string
	for i, line := range lines {
		m := scanOf.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if m[1] != "" {
			out = append(out, m[1])
			continue
		}
		seeks, filters := false, false
		for _, next := range lines[i+1:] {
			if strings.Contains(next, "->") {
				break
			}
			seeks = seeks || strings.Contains(next, "Index Cond:")
			filters = filters || strings.Contains(next, "Filter:")
		}
		if filters && !seeks {
			out = append(out, m[2])
		}
	}
	return out
}

// walkFree is what Explain turns off. The joins and the sort too, because on a test's
// small tables a hash join reads one side whole though an index would serve it, and a
// sort beats an index that has the order already, and that is the size of the table
// and not the shape of the statement.
var walkFree = []string{"seqscan", "hashjoin", "mergejoin", "material", "sort"}

// seeksOnly adds the plain index scans, leaving the bitmap ones, which exist only
// with an index condition to build the bitmap from. So on an empty table, where every
// index costs the same and the planner may walk the wrong one, a whole table still
// read in this plan, by a disabled path of either kind, is one no index can serve.
var seeksOnly = append(append([]string{}, walkFree...), "indexscan", "indexonlyscan")

// Explain plans a statement with the alternatives to an index turned off.
func Explain(ctx context.Context, pool *pgxpool.Pool, s Statement) (string, error) {
	return explain(ctx, pool, s, walkFree)
}

func explain(ctx context.Context, pool *pgxpool.Pool, s Statement, off []string) (string, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, name := range off {
		if _, err := tx.Exec(ctx, `SET LOCAL enable_`+name+` = off`); err != nil {
			return "", err
		}
	}
	rows, err := tx.Query(ctx, "EXPLAIN "+s.SQL, s.Args...)
	if err != nil {
		return "", err
	}
	lines, err := pgx.CollectRows(rows, pgx.RowTo[string])
	return strings.Join(lines, "\n"), err
}

// Find explains each distinct statement on a core table and answers those reading a
// table whole, as "table: statement", with how many it looked at. allowed says which
// of them are all right, and why is the caller's to record.
func Find(ctx context.Context, pool *pgxpool.Pool, sent []Statement, allowed func(table, sql string) bool) ([]string, int, error) {
	seen := map[string]bool{}
	var found []string
	for _, s := range sent {
		if !strings.Contains(s.SQL, "core.") || seen[s.SQL] {
			continue
		}
		seen[s.SQL] = true
		plan, err := Explain(ctx, pool, s)
		if err != nil {
			return found, len(seen), fmt.Errorf("explaining %s: %w", strings.Join(strings.Fields(s.SQL), " "), err)
		}
		whole := ReadWhole(plan)
		if len(whole) == 0 {
			continue
		}
		bitmap, err := explain(ctx, pool, s, seeksOnly)
		if err != nil {
			return found, len(seen), fmt.Errorf("explaining %s: %w", strings.Join(strings.Fields(s.SQL), " "), err)
		}
		for _, table := range ReadWhole(bitmap) {
			if slices.Contains(whole, table) && !allowed(table, s.SQL) {
				found = append(found, table+": "+strings.Join(strings.Fields(s.SQL), " ")+"\n"+bitmap)
			}
		}
	}
	return found, len(seen), nil
}
