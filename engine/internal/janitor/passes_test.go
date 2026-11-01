package janitor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/store"
)

// plantBacklog widens an expired session into n more for the same person and
// client, and answers the prefix they share.
func plantBacklog(t *testing.T, pool *pgxpool.Pool, n int) string {
	t.Helper()
	ctx := context.Background()
	sid := plantExpiredSession(t, pool)
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		SELECT s.sid || '-' || g, decode(md5(s.sid || g), 'hex'), s.org_id, s.user_id, s.acr, s.amr, s.auth_time, s.not_after
		  FROM core.sessions s, generate_series(1, $2::int) g WHERE s.sid = $1`, sid, n); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.session_clients (sid, client_id)
		SELECT c.sid || '-' || g, c.client_id FROM core.session_clients c, generate_series(1, $2::int) g
		 WHERE c.sid = $1`, sid, n); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM core.outbox WHERE payload->>'sid' LIKE $1 || '%'`, sid)
		_, _ = pool.Exec(c, `DELETE FROM core.session_clients WHERE sid LIKE $1 || '%'`, sid)
		_, _ = pool.Exec(c, `DELETE FROM core.sessions WHERE sid LIKE $1 || '%'`, sid)
	})
	return sid
}

func stillLive(t *testing.T, pool *pgxpool.Pool, prefix string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM core.sessions
		WHERE sid LIKE $1 || '%' AND revoked_at IS NULL`, prefix).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A backlog past one batch was 500 sessions a minute however large it was. One
// pass works through it, and each session is told of once, by its own sid.
func TestABacklogIsWorkedThroughInOnePass(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	extra := sessionBatch*2 + 50
	prefix := plantBacklog(t, pool, extra)
	for pass := 0; pass < 10 && stillLive(t, pool, prefix) > 0; pass++ {
		if _, err := RunOnce(ctx, pool, discard()); err != nil {
			t.Fatal(err)
		}
	}
	if n := stillLive(t, pool, prefix); n != 0 {
		t.Fatalf("%d sessions outlived the passes", n)
	}
	var notices, sids int
	if err := pool.QueryRow(ctx, `SELECT count(*), count(DISTINCT payload->>'sid') FROM core.outbox
		WHERE topic = 'backchannel_logout' AND payload->>'sid' LIKE $1 || '%'`, prefix).Scan(&notices, &sids); err != nil {
		t.Fatal(err)
	}
	if notices != extra+1 || sids != extra+1 {
		t.Errorf("%d notices for %d sids, wanting one each for %d sessions", notices, sids, extra+1)
	}
}

// A pass ends, and says what it left: a backlog must not run into the next one.
func TestAPassStopsAtItsBudgetAndSaysWhatItLeft(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	prefix := plantBacklog(t, pool, sessionBatch+10)
	var st Stats
	var err error
	for try := 0; try < 10; try++ {
		if st, err = runPass(ctx, pool, discard(), 0); err != nil {
			t.Fatal(err)
		}
		if !st.Skipped {
			break
		}
	}
	if !slices.Contains(st.Behind, "expired sessions") {
		t.Fatalf("a pass out of budget reports %v", st.Behind)
	}
	if stillLive(t, pool, prefix) == 0 {
		t.Fatal("a pass with no budget worked through more than one round")
	}
	for pass := 0; pass < 10 && stillLive(t, pool, prefix) > 0; pass++ {
		if _, err := RunOnce(ctx, pool, discard()); err != nil {
			t.Fatal(err)
		}
	}
	if n := stillLive(t, pool, prefix); n != 0 {
		t.Errorf("the next pass left %d", n)
	}
}

// taking is a sweep with so many rows left, one a batch.
func taking(name string, left *int, order *[]string) sweep {
	return sweep{name: name, limit: 1, work: func(context.Context, pgx.Tx, int) (int64, error) {
		if *left == 0 {
			return 0, nil
		}
		*left--
		*order = append(*order, name)
		return 1, nil
	}}
}

// A backlog in one table must not starve every other: sessions come first in the
// list, and a million of them would otherwise be all a pass ever did.
func TestEverySweepGetsABatchBeforeAnyGetsASecond(t *testing.T) {
	pool := newPool(t)
	a, b, c := 3, 1, 2
	var order []string
	var st Stats
	work := []sweep{taking("a", &a, &order), taking("b", &b, &order), taking("c", &c, &order)}
	for try := 0; try < 10; try++ {
		order, st = nil, Stats{}
		a, b, c = 3, 1, 2
		if err := runSweeps(context.Background(), pool, work, time.Hour, &st); err != nil {
			t.Fatal(err)
		}
		if !st.Skipped {
			break
		}
	}
	if got := strings.Join(order, ""); got != "abcaca" {
		t.Errorf("the batches ran in the order %q", got)
	}
}

// One table that cannot be swept must not leave the rest to grow, and it was a
// single transaction: a failure anywhere rolled back everything before it.
func TestAFailedSweepStopsOnlyItself(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	after, ran := 1, 0
	var order []string
	broken := errors.New("this table cannot be swept")
	work := []sweep{
		{name: "broken", limit: 1, work: func(context.Context, pgx.Tx, int) (int64, error) { ran++; return 0, broken }},
		taking("after", &after, &order),
	}
	var st Stats
	var err error
	for try := 0; try < 10; try++ {
		st, after, ran, order = Stats{}, 1, 0, nil
		if err = runSweeps(ctx, pool, work, time.Hour, &st); !st.Skipped {
			break
		}
	}
	if !errors.Is(err, broken) || !strings.Contains(err.Error(), "broken") {
		t.Errorf("the pass answered %v", err)
	}
	if len(order) != 1 {
		t.Error("a sweep after the broken one did not run")
	}
	if ran != 1 {
		t.Errorf("the broken sweep was tried %d times in a pass", ran)
	}
}

// What makes it many short transactions rather than one long one: what a batch
// did can be seen from outside before the next has started.
func TestEachBatchCommitsBeforeTheNextBegins(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	sid := plantExpiredSession(t, pool)
	var ended bool
	work := []sweep{
		{name: "end it", limit: 1000, work: func(ctx context.Context, tx pgx.Tx, _ int) (int64, error) {
			_, err := store.TerminateSessions(ctx, tx, sid, "", store.ReasonExpired)
			return 1, err
		}},
		{name: "look", limit: 1000, work: func(ctx context.Context, _ pgx.Tx, _ int) (int64, error) {
			return 0, pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM core.sessions WHERE sid = $1`, sid).Scan(&ended)
		}},
	}
	var st Stats
	for try := 0; try < 10; try++ {
		st = Stats{}
		if err := runSweeps(ctx, pool, work, time.Hour, &st); err != nil {
			t.Fatal(err)
		}
		if !st.Skipped {
			break
		}
	}
	if !ended {
		t.Error("the first batch was not committed when the second began")
	}
}

// A peer that takes the lock partway through ends this pass, which is not the same
// as a pass that was skipped: what was done was done.
func TestAPeerArrivingMidPassDoesNotMakeItASkippedOne(t *testing.T) {
	pool := newPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	defer close(release)
	var swept int64
	second := false
	work := []sweep{
		{name: "first", limit: 1000, into: &swept, work: func(ctx context.Context, _ pgx.Tx, _ int) (int64, error) {
			// A peer queues for the lock this batch holds, and has it the moment
			// this batch commits, ahead of the next one's try.
			go func() {
				tx, err := pool.Begin(ctx)
				if err != nil {
					return
				}
				defer func() { _ = tx.Rollback(context.Background()) }()
				if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID); err != nil {
					return
				}
				<-release
			}()
			// Ten seconds, for a suite on a busy machine; the answer is usually at once.
			for range 1000 {
				var waiting int
				if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'
					AND objid = $1::bigint AND NOT granted`, lockID).Scan(&waiting); err != nil {
					return 0, err
				}
				if waiting > 0 {
					return 3, nil
				}
				time.Sleep(10 * time.Millisecond)
			}
			return 0, errors.New("the peer never queued")
		}},
		{name: "second", limit: 1000, work: func(context.Context, pgx.Tx, int) (int64, error) {
			second = true
			return 0, nil
		}},
	}
	var st Stats
	if err := runSweeps(ctx, pool, work, time.Hour, &st); err != nil {
		t.Fatal(err)
	}
	if st.Skipped || swept != 3 {
		t.Errorf("skipped %v after sweeping %d", st.Skipped, swept)
	}
	if second {
		t.Error("the pass went on while a peer held the lock")
	}
}

type countingTracer struct{ n atomic.Int64 }

func (c *countingTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.n.Add(1)
	return ctx
}

func (c *countingTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// Ending a thousand sessions takes the statements ending one takes. It took a
// handful for each, and a pass of 500 was thousands of round trips.
func TestABatchOfSessionsTakesNoMoreStatementsThanOne(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set; skipping database-backed tests")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_maintenance")
		return err
	}
	spent := &countingTracer{}
	cfg.ConnConfig.Tracer = spent
	ctx := context.Background()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	plantBacklog(t, pool, 400)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	before := spent.n.Load()
	swept, err := store.SweepExpiredSessions(ctx, tx, 400)
	if err != nil {
		t.Fatal(err)
	}
	if used := spent.n.Load() - before; swept < 400 || used > 8 {
		t.Errorf("ending %d sessions took %d statements", swept, used)
	}
}

// A session somebody is signing out of at this moment holds a row lock. The sweep
// goes round it: neither of them waits, and the next batch finds it if it is
// still there.
func TestASessionInUseIsNotWaitedFor(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	sid := plantExpiredSession(t, pool)
	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err := holder.Exec(ctx, `SELECT 1 FROM core.sessions WHERE sid = $1 FOR UPDATE`, sid); err != nil {
		t.Fatal(err)
	}
	soon, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := pool.Begin(soon)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := store.SweepExpiredSessions(soon, tx, 1<<20); err != nil {
		t.Fatalf("the sweep waited for a held session: %v", err)
	}
	var revoked bool
	if err := tx.QueryRow(soon, `SELECT revoked_at IS NOT NULL FROM core.sessions WHERE sid = $1`, sid).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Error("the sweep ended a session somebody else held")
	}
}

// A sweep deletes what it was told it may, and leaves the rest for the next batch.
func TestASweepStopsAtItsLimit(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO core.dpop_seen_jtis (jkt, jti, expires_at)
		SELECT 'limit', gen_random_uuid()::text, now() - interval '1 hour' FROM generate_series(1, 5)`); err != nil {
		t.Fatal(err)
	}
	n, err := store.SweepExpiredDPoPProofs(ctx, tx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("a limit of 2 deleted %d", n)
	}
}

// Every purge is bounded and every purge is run: an unbounded one is the long
// transaction this package stopped having, and one nobody calls is a table that
// only grows. Read from the source, so the next one is held to it too.
func TestEveryPurgeIsBoundedAndRun(t *testing.T) {
	files, err := filepath.Glob("../store/*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("reading the store: %v", err)
	}
	here, err := os.ReadFile("janitor.go")
	if err != nil {
		t.Fatal(err)
	}
	head := regexp.MustCompile(`(?m)^func ((?:Purge|Sweep)\w+)\(([^\n]*)`)
	seen := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(src)
		for _, m := range head.FindAllStringSubmatchIndex(text, -1) {
			fn, params := text[m[2]:m[3]], text[m[4]:m[5]]
			seen++
			if !strings.Contains(string(here), "store."+fn) {
				t.Errorf("%s is never run by a pass", fn)
			}
			if !strings.Contains(params, "limit int") && !strings.Contains(params, "batch int") {
				t.Errorf("%s takes no limit", fn)
			}
			body := text[m[1]:]
			if end := strings.Index(body, "\n}\n"); end > 0 {
				body = body[:end]
			}
			if !strings.Contains(body, "LIMIT $") {
				t.Errorf("%s has no LIMIT in it", fn)
			}
		}
	}
	if seen < 20 {
		t.Errorf("found %d purges, so the scan is broken", seen)
	}
}
