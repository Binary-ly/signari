package store

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
)

// What the one lock on the audit chain lets through, at a round trip a real
// database is away from. On loopback a round trip is nothing and the lock looks
// free; the ceiling is the number of round trips made while holding it, so that
// is what this varies. A measurement, recorded in the roadmap, not a guard: a
// figure from one machine under other work is no reason to fail a build.
func TestAuditedTransactionRate(t *testing.T) {
	if os.Getenv("MEASURE_AUDIT") == "" {
		t.Skip("a measurement; MEASURE_AUDIT=1 runs it")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(os.Getenv("SIGNARI_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	audit.SetPublisher(AuditPublisher)
	t.Cleanup(func() { audit.SetPublisher(nil) })

	target := net.JoinHostPort(cfg.ConnConfig.Host, fmt.Sprint(cfg.ConnConfig.Port))
	for _, oneWay := range []time.Duration{0, 500 * time.Microsecond} {
		c := cfg.Copy()
		c.MaxConns = 70
		if oneWay > 0 {
			host, port, err := net.SplitHostPort(delayed(t, target, oneWay))
			if err != nil {
				t.Fatal(err)
			}
			var n uint16
			if _, err := fmt.Sscan(port, &n); err != nil {
				t.Fatal(err)
			}
			c.ConnConfig.Host, c.ConnConfig.Port = host, n
			c.ConnConfig.TLSConfig, c.ConnConfig.Fallbacks = nil, nil
		}
		pool, err := pgxpool.NewWithConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		var orgID string
		if err := pool.QueryRow(ctx, `SELECT id::text FROM core.organizations LIMIT 1`).Scan(&orgID); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		for range 200 {
			if err := pool.QueryRow(ctx, `SELECT 1`).Scan(new(int)); err != nil {
				t.Fatal(err)
			}
		}
		rtt := time.Since(start) / 200
		for _, writers := range []int{1, 4, 16, 64} {
			rate, p99 := auditRate(t, pool, orgID, writers)
			t.Logf("round trip %8s, %2d writers: %6.0f audited tx/s, p99 %s", rtt.Round(10*time.Microsecond),
				writers, rate, p99.Round(100*time.Microsecond))
		}
		pool.Close()
	}
}

// A subscription whose delivery cannot be queued must not stop what is being
// recorded. Failing is a statement failing, and that ends the transaction it is
// in, so without a savepoint a broken subscription refused every sign-in at its
// commit while audit.Write said it had not.
func TestADeliveryThatCannotBeQueuedStopsNothing(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	// Rolled back, the trigger with it: visible to this connection, residue for nobody.
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var orgID string
	if err := tx.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://delivery-probe.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'delivery-probe', 'probe' FROM i RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	root, err := keys.NewRootKey("test", bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateSubscription(ctx, tx, root, orgID, "broken", "https://subscriber.example/hook", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		CREATE FUNCTION pg_temp.refuse_delivery() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'refused'; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `CREATE TRIGGER refuse_delivery BEFORE INSERT ON core.event_deliveries
		FOR EACH ROW EXECUTE FUNCTION pg_temp.refuse_delivery()`); err != nil {
		t.Fatal(err)
	}
	audit.SetPublisher(AuditPublisher)
	t.Cleanup(func() { audit.SetPublisher(nil) })

	if err := audit.Write(ctx, tx, audit.Event{Type: "login.failed", OrgID: orgID}); err != nil {
		t.Fatalf("the write failed with the delivery: %v", err)
	}
	var written int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE org_id = $1::uuid`, orgID).Scan(&written); err != nil {
		t.Fatalf("the transaction did not survive the delivery: %v", err)
	}
	if written != 1 {
		t.Errorf("%d rows were written", written)
	}
}

// The lock on the chain is held to the commit and every audited transaction in
// the deployment waits behind it, so nothing an audited write does may come after
// the statement that takes it. The read of the subscriptions used to, and with
// the tail and the insert it was what kept a networked database to 146 a second.
func TestNothingIsAskedAfterTheChainsLock(t *testing.T) {
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	seen := &askedInOrder{}
	cfg.Tracer = seen
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var orgID string
	if err := tx.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://lock-probe.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'lock-probe', 'probe' FROM i RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	audit.SetPublisher(AuditPublisher)
	t.Cleanup(func() { audit.SetPublisher(nil) })

	seen.asked = nil
	if err := audit.Write(ctx, tx, audit.Event{Type: "login.failed", OrgID: orgID}); err != nil {
		t.Fatal(err)
	}
	if len(seen.asked) < 2 || !strings.Contains(seen.asked[len(seen.asked)-1], "core.audit_append") {
		t.Errorf("the lock is not the last thing asked: %q", seen.asked)
	}
	if !slices.ContainsFunc(seen.asked, func(s string) bool { return strings.Contains(s, "event_subscriptions") }) {
		t.Errorf("nothing read the subscriptions: %q", seen.asked)
	}
}

// askedInOrder remembers what a connection was asked.
type askedInOrder struct{ asked []string }

func (a *askedInOrder) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	a.asked = append(a.asked, d.SQL)
	return ctx
}

func (*askedInOrder) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func auditRate(t *testing.T, pool *pgxpool.Pool, orgID string, writers int) (float64, time.Duration) {
	t.Helper()
	ctx := context.Background()
	const window = 3 * time.Second
	var done atomic.Int64
	var mu sync.Mutex
	var took []time.Duration
	var wg sync.WaitGroup
	stop := time.Now().Add(window)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var mine []time.Duration
			for time.Now().Before(stop) {
				began := time.Now()
				tx, err := pool.Begin(ctx)
				if err != nil {
					t.Error(err)
					return
				}
				if err := audit.Write(ctx, tx, audit.Event{Type: "measure.audit_rate", OrgID: orgID,
					Detail: map[string]any{"writers": writers}}); err != nil {
					_ = tx.Rollback(ctx)
					t.Error(err)
					return
				}
				if err := tx.Commit(ctx); err != nil {
					t.Error(err)
					return
				}
				mine = append(mine, time.Since(began))
				done.Add(1)
			}
			mu.Lock()
			took = append(took, mine...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(took) == 0 {
		return 0, 0
	}
	slices.Sort(took)
	return float64(done.Load()) / window.Seconds(), took[len(took)*99/100]
}

// delayed is a listener that passes each read on to target after oneWay, in both
// directions, and says where it listens.
func delayed(t *testing.T, target string, oneWay time.Duration) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	pump := func(from, to net.Conn) {
		defer func() { _ = to.Close() }()
		buf := make([]byte, 64<<10)
		for {
			n, err := from.Read(buf)
			if n > 0 {
				time.Sleep(oneWay)
				if _, werr := to.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go func() {
		for {
			client, err := l.Accept()
			if err != nil {
				return
			}
			server, err := net.Dial("tcp", target)
			if err != nil {
				_ = client.Close()
				continue
			}
			go pump(client, server)
			go pump(server, client)
		}
	}()
	return l.Addr().String()
}
