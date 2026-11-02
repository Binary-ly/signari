package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/store/storetest"
)

// A connection with a cap has room for that many and no more (8.29): one that has
// finished gives its place back, and so does one whose process died without saying so,
// or a full connection stays full for good.
func TestACappedConnectionHoldsItsCapAndGivesPlacesBack(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	n := time.Now().UnixNano()
	var instance, org, user string
	if err := pool.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name) VALUES ($1, 'probe')
		RETURNING id::text`, fmt.Sprintf("https://racreserve-%d.invalid", n)).Scan(&instance); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO core.organizations (instance_id, slug, display_name)
		VALUES ($1::uuid, $2, 'probe') RETURNING id::text`, instance, fmt.Sprintf("racreserve-%d", n)).
		Scan(&org); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM core.rac_sessions WHERE org_id = $1::uuid`, org)
	})
	storetest.Forget(t, pool, org)
	if err := pool.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, email) VALUES ($1::uuid,
		sha256(gen_random_uuid()::text::bytea) || sha256(gen_random_uuid()::text::bytea), $2) RETURNING id::text`,
		org, fmt.Sprintf("racreserve-%d@example.test", n)).Scan(&user); err != nil {
		t.Fatal(err)
	}
	if _, err := AddRACConnection(ctx, pool, nil, org, RACSpec{Slug: "desk", Protocol: "rdp", Host: "10.0.4.21"}); err != nil {
		t.Fatal(err)
	}
	two := 2
	if err := SetRACLimits(ctx, pool, org, "desk", &two, nil); err != nil {
		t.Fatal(err)
	}
	conn, err := LoadRACConnection(ctx, pool, org, "desk")
	if err != nil {
		t.Fatal(err)
	}
	if conn.MaxConnections != 2 {
		t.Fatalf("the cap read back as %d", conn.MaxConnections)
	}

	reserve := func(want error) string {
		t.Helper()
		id, err := ReserveRACSession(ctx, pool, conn, user)
		if !errors.Is(err, want) {
			t.Fatalf("reserving answered %v, want %v", err, want)
		}
		return id
	}
	first := reserve(nil)
	second := reserve(nil)
	reserve(ErrRACFull)

	if err := EndRACSession(ctx, pool, first, "closed"); err != nil {
		t.Fatal(err)
	}
	third := reserve(nil)
	reserve(ErrRACFull)

	// A session nobody has seen for longer than the stale limit is taken for a process
	// that died; one that is merely quiet still counts, so a place is not given away
	// while somebody is using it.
	if _, err := pool.Exec(ctx, `UPDATE core.rac_sessions SET last_seen_at = now() - make_interval(secs => $2)
		WHERE id = $1::uuid`, second, (racSessionStale - time.Minute).Seconds()); err != nil {
		t.Fatal(err)
	}
	reserve(ErrRACFull)
	if _, err := pool.Exec(ctx, `UPDATE core.rac_sessions SET last_seen_at = now() - make_interval(secs => $2)
		WHERE id = $1::uuid`, second, (racSessionStale + time.Minute).Seconds()); err != nil {
		t.Fatal(err)
	}
	fourth := reserve(nil)
	reserve(ErrRACFull)

	// A session that says it is still there keeps its place past the stale limit.
	if _, err := pool.Exec(ctx, `UPDATE core.rac_sessions SET last_seen_at = now() - make_interval(secs => $2)
		WHERE id = $1::uuid`, third, (racSessionStale + time.Minute).Seconds()); err != nil {
		t.Fatal(err)
	}
	if err := TouchRACSession(ctx, pool, third); err != nil {
		t.Fatal(err)
	}
	reserve(ErrRACFull)

	// Twenty arriving at once, with no place left but the two these end: exactly two
	// get in, whatever order they arrive in.
	for _, id := range []string{third, fourth} {
		if err := EndRACSession(ctx, pool, id, "closed"); err != nil {
			t.Fatal(err)
		}
	}
	// Each on a connection already open, released together: a pool that has to open
	// them serves the attempts one after another, and the race never happens.
	settings, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	settings.MaxConns = 20
	racing, err := pgxpool.NewWithConfig(ctx, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer racing.Close()
	var warm []*pgxpool.Conn
	for range 20 {
		c, err := racing.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		warm = append(warm, c)
	}
	for _, c := range warm {
		c.Release()
	}
	var wg sync.WaitGroup
	got := make(chan error, 20)
	start := make(chan struct{})
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := ReserveRACSession(ctx, racing, conn, user)
			got <- err
		}()
	}
	close(start)
	wg.Wait()
	close(got)
	admitted, refused := 0, 0
	for err := range got {
		switch {
		case err == nil:
			admitted++
		case errors.Is(err, ErrRACFull):
			refused++
		default:
			t.Errorf("a reservation failed: %v", err)
		}
	}
	if admitted != 2 || refused != 18 {
		t.Errorf("of twenty, %d were admitted and %d refused; the cap is two", admitted, refused)
	}

	// No cap, no count: a connection without one takes everybody.
	zero := 0
	if err := SetRACLimits(ctx, pool, org, "desk", &zero, nil); err != nil {
		t.Fatal(err)
	}
	if conn, err = LoadRACConnection(ctx, pool, org, "desk"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		reserve(nil)
	}
}

// A limit that cannot mean what it says is refused, before anything is written.
func TestARACLimitIsChecked(t *testing.T) {
	over, negative, month := racMaxDuration+1, -1, racMaxDuration
	for _, bad := range []struct{ connections, duration *int }{{&negative, nil}, {nil, &negative}, {nil, &over}} {
		if err := CheckRACLimits(bad.connections, bad.duration); !errors.Is(err, ErrRACLimit) {
			t.Errorf("%v answered %v", bad, err)
		}
	}
	if err := CheckRACLimits(nil, &month); err != nil {
		t.Errorf("a month is the limit, not over it: %v", err)
	}
}
