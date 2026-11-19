package audit

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// appendStatements remembers the appends a pool was asked to make.
type appendStatements struct {
	mu   sync.Mutex
	seen []string
}

func (a *appendStatements) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "core.audit_append") {
		a.mu.Lock()
		a.seen = append(a.seen, strings.Join(strings.Fields(d.SQL), " "))
		a.mu.Unlock()
	}
	return ctx
}

func (a *appendStatements) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// count is how many appends called fn: "core.audit_append(" or "core.audit_append_many(".
func (a *appendStatements) count(fn string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, s := range a.seen {
		if strings.Contains(s, fn) {
			n++
		}
	}
	return n
}

// gatedPool is a pool whose first transaction waits to begin until the test opens the
// gate, so the records that arrive meanwhile wait for it, as they would for a slow one.
type gatedPool struct {
	*pgxpool.Pool
	once    sync.Once
	entered chan struct{}
	gate    chan struct{}
}

func (g *gatedPool) Begin(ctx context.Context) (pgx.Tx, error) {
	first := false
	g.once.Do(func() { first = true })
	if first {
		close(g.entered)
		<-g.gate
	}
	return g.Pool.Begin(ctx)
}

func detachedFixture(t *testing.T) (*gatedPool, *appendStatements) {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set; skipping database-backed tests")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	seen := &appendStatements{}
	cfg.ConnConfig.Tracer = seen
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_maintenance")
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return &gatedPool{Pool: pool, entered: make(chan struct{}), gate: make(chan struct{})}, seen
}

// chainTail is the newest entry committed, read through db.
func chainTail(t *testing.T, db *gatedPool) int64 {
	t.Helper()
	var id int64
	if err := db.Pool.QueryRow(context.Background(),
		`SELECT COALESCE(max(id), 0) FROM core.audit_events`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// writeGated writes events[0] alone, holds its transaction at the gate until the others
// have joined the group behind it, then lets them all through and answers each write's
// error. The records are committed: these are real links, appended by the real function,
// and the trail is append-only for tests too.
func writeGated(t *testing.T, d *Detached, db *gatedPool, events []Event) []error {
	t.Helper()
	ctx := context.Background()
	errs := make([]error, len(events))
	var wg sync.WaitGroup
	write := func(i int) {
		defer wg.Done()
		errs[i] = d.Write(ctx, db, events[i])
	}
	wg.Add(1)
	go write(0)
	<-db.entered
	for i := 1; i < len(events); i++ {
		wg.Add(1)
		go write(i)
	}
	deadline := time.Now().Add(10 * time.Second)
	for d.waiting() < len(events)-1 {
		if time.Now().After(deadline) {
			joined := d.waiting()
			close(db.gate)
			wg.Wait()
			t.Fatalf("only %d of %d records joined the group behind the first", joined, len(events)-1)
		}
		time.Sleep(2 * time.Millisecond)
	}
	close(db.gate)
	wg.Wait()
	return errs
}

// verifyFrom checks the chain from the entry the test's records followed.
func verifyFrom(t *testing.T, db *gatedPool, from int64) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	broken, checked, err := VerifyFrom(ctx, tx, from)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("the chain is broken at id %d after records appended together (checked %d)", broken, checked)
	}
}

// writtenOrder is the detail "i" of each record carrying the correlation id, in id order.
func writtenOrder(t *testing.T, db *gatedPool, correlation string) []int {
	t.Helper()
	rows, err := db.Pool.Query(context.Background(),
		`SELECT (detail->>'i')::int FROM core.audit_events WHERE correlation_id = $1::uuid ORDER BY id`, correlation)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[int])
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// The records that arrive while one is being written are appended by one statement, one
// transaction, after it: the chain's lock and its commit paid once for all of them. Each
// is committed when its write returns, and the chain verifies across them.
func TestRecordsArrivingTogetherAreAppendedByOneStatement(t *testing.T) {
	db, seen := detachedFixture(t)
	from := chainTail(t, db)
	correlation := uuid.NewString()
	const n = 16
	events := make([]Event, n)
	for i := range events {
		events[i] = Event{Type: "test.detached", CorrelationID: correlation, Detail: map[string]any{"i": i}}
	}
	for i, err := range writeGated(t, NewDetached(), db, events) {
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if one, many := seen.count("core.audit_append("), seen.count("core.audit_append_many("); one != 1 || many != 1 {
		t.Errorf("%d records took %d appends of one and %d of many, want the first alone and the rest in one",
			n, one, many)
	}
	got := writtenOrder(t, db, correlation)
	if len(got) != n {
		t.Fatalf("%d of %d records were committed when their writes returned", len(got), n)
	}
	if got[0] != 0 {
		t.Errorf("the record that was being written when the others arrived is not first: %v", got)
	}
	verifyFrom(t, db, from)
}

// A record its group cannot append is written again on its own, and so is every other in
// the group: the one that fails fails alone, and the others are committed.
func TestARecordThatCannotBeAppendedTakesNoOtherWithIt(t *testing.T) {
	db, _ := detachedFixture(t)
	from := chainTail(t, db)
	correlation := uuid.NewString()
	event := func(i int, retention string) Event {
		return Event{Type: "test.detached", Retention: retention, CorrelationID: correlation,
			Detail: map[string]any{"i": i}}
	}
	// A retention class the table's CHECK refuses: put in its canonical form like any
	// other, and refused by the insert, and so by the statement appending its group. (Not
	// an organisation that does not exist: migration 0043 dropped that foreign key, so
	// deleting an organisation never rewrites a record.)
	errs := writeGated(t, NewDetached(), db,
		[]Event{event(0, ""), event(1, ""), event(2, "kept-by-nobody"), event(3, "")})
	for i, err := range errs {
		if (err != nil) != (i == 2) {
			t.Errorf("record %d: %v, want only record 2 refused", i, err)
		}
	}
	got := writtenOrder(t, db, correlation)
	if len(got) != 3 || got[0] != 0 {
		t.Fatalf("committed %v, want records 0, 1 and 3, 0 first", got)
	}
	verifyFrom(t, db, from)
}
