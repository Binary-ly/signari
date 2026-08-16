package audit

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestConcurrentAppendsDoNotForkTheChain.
//
// The chain is what makes the log tamper-evident: each entry hashes its
// predecessor, so removing or editing one breaks every entry after it. That
// only means something if the chain is a LINE. Two entries claiming the same
// predecessor is a fork, and a fork is indistinguishable from a deletion when
// the chain is verified.
//
// This was found by running two instances against one database and watching the
// audit tests fail on data nobody had touched:
//
//	id 135  prev=c28a4116
//	id 136  prev=c28a4116     <- both after 134
//
// It is NOT specific to more than one instance. Two concurrent sign-ins on a
// single instance do the same thing; running two just made it frequent enough
// to notice.
//
// The original guard was FOR UPDATE on the tail row, which does not serialise
// appenders under READ COMMITTED: the blocked transaction re-reads THAT ROW,
// finds it unchanged, and appends after it -- while the transaction it waited
// for has already appended after it too.
func TestConcurrentAppendsDoNotForkTheChain(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	orgID, err := anyOrg(ctx, pool)
	if err != nil {
		t.Skipf("no organisation to attribute events to: %v", err)
	}

	marker := fmt.Sprintf("concurrency-probe-%d", time.Now().UnixNano())

	const writers = 12
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tx, err := pool.Begin(ctx)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = tx.Rollback(ctx) }()

			if err := Write(ctx, tx, Event{
				Type: marker, OrgID: orgID,
				Detail: map[string]any{"writer": i},
			}); err != nil {
				errs <- err
				return
			}
			if err := tx.Commit(ctx); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("writing an audit event: %v", err)
	}

	// No two entries anywhere may share a predecessor.
	var forks int
	var detail string
	err = pool.QueryRow(ctx, `
		SELECT count(*), COALESCE(max(ids), '')
		FROM (
			SELECT string_agg(id::text, ',' ORDER BY id) AS ids
			FROM core.audit_events
			WHERE prev_hash IS NOT NULL
			GROUP BY prev_hash
			HAVING count(*) > 1
		) f`).Scan(&forks, &detail)
	if err != nil {
		t.Fatal(err)
	}
	if forks > 0 {
		t.Fatalf("%d fork(s) in the audit chain; one is at rows %s.\n"+
			"Two entries claiming the same predecessor is indistinguishable from "+
			"a deleted entry, so verification reports tampering where there was "+
			"none -- and a log that cries wolf is a log nobody checks.",
			forks, detail)
	}
}

func anyOrg(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	var id string
	err := pool.QueryRow(ctx, `SELECT id::text FROM core.organizations LIMIT 1`).Scan(&id)
	return id, err
}
