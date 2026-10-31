package directory

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// statementCount counts what a pool sends, so a cost that grows with the plan
// shows as a number rather than as a slow machine.
type statementCount struct{ n atomic.Int64 }

func (c *statementCount) TraceQueryStart(ctx context.Context, _ *pgx.Conn,
	_ pgx.TraceQueryStartData) context.Context {
	c.n.Add(1)
	return ctx
}

func (c *statementCount) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func countedPool(t testing.TB, dsn string) (*pgxpool.Pool, *statementCount) {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	spent := &statementCount{}
	cfg.ConnConfig.Tracer = spent
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool, spent
}

func people(suffix string, from, n int) []RemoteUser {
	out := make([]RemoteUser, n)
	for i := range out {
		id := from + i
		out[i] = RemoteUser{ID: fmt.Sprintf("r%d", id), Email: fmt.Sprintf("p%d-%s@example.test", id, suffix),
			Name: fmt.Sprintf("Person %d", id)}
	}
	return out
}

// A sync is the same few statements however many people it brings (7.16). It
// was three for each person created or updated and one for each reactivated.
func TestASyncCostsTheSameHoweverManyItBrings(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	pool, spent := countedPool(t, dsn)
	ctx := context.Background()
	orgID, sourceID := fixture(t, pool)
	suffix := rnd(t)

	sync := func(remote []RemoteUser) int64 {
		t.Helper()
		local, err := LoadLocal(ctx, pool, sourceID, orgID)
		if err != nil {
			t.Fatal(err)
		}
		plan := BuildPlan(remote, local, "deactivate", 100)
		before := spent.n.Load()
		if err := Apply(ctx, pool, sourceID, orgID, plan); err != nil {
			t.Fatal(err)
		}
		return spent.n.Load() - before
	}
	rename := func(in []RemoteUser, n int, to string) []RemoteUser {
		out := append([]RemoteUser(nil), in...)
		for i := 0; i < n; i++ {
			out[i].Name = to
		}
		return out
	}

	few := people(suffix, 0, 3)
	all := append(append([]RemoteUser(nil), few...), people(suffix, 3, 100)...)
	createFew := sync(few)
	createMany := sync(all)
	if createFew != createMany {
		t.Errorf("creating 3 took %d statements and 100 took %d", createFew, createMany)
	}
	updateFew := sync(rename(all, 3, "Renamed"))
	updateMany := sync(rename(all, len(all), "Renamed again"))
	if updateFew != updateMany {
		t.Errorf("updating 3 took %d statements and 103 took %d", updateFew, updateMany)
	}

	suspended := func(n int) []RemoteUser {
		out := rename(all, len(all), "Renamed again")
		for i := 0; i < n; i++ {
			out[i].Suspended = true
		}
		return out
	}
	sync(suspended(3))
	reactivateFew := sync(suspended(0))
	sync(suspended(100))
	reactivateMany := sync(suspended(0))
	if reactivateFew != reactivateMany {
		t.Errorf("reactivating 3 took %d statements and 100 took %d", reactivateFew, reactivateMany)
	}

	var active, links int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE u.status = 'active'), count(l.remote_id)
		FROM core.users u LEFT JOIN core.directory_links l ON l.user_id = u.id AND l.source_id = $2::uuid
		WHERE u.org_id = $1::uuid`, orgID, sourceID).Scan(&active, &links); err != nil {
		t.Fatal(err)
	}
	if active != len(all) || links != len(all) {
		t.Errorf("%d active and %d linked, want %d of each", active, links, len(all))
	}
}

// A paged fetch can return somebody twice, and a sync of them worked a
// statement at a time. One statement may not touch a row twice, so they are
// one person here too, and the later entry is the one kept.
func TestSomebodyListedTwiceIsOnePerson(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	orgID, sourceID := fixture(t, pool)
	suffix := rnd(t)
	sync := func(remote ...RemoteUser) {
		t.Helper()
		local, err := LoadLocal(ctx, pool, sourceID, orgID)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, pool, sourceID, orgID, BuildPlan(remote, local, "deactivate", 100)); err != nil {
			t.Fatal(err)
		}
	}
	state := func() (users, links int, name string) {
		t.Helper()
		if err := pool.QueryRow(ctx, `
			SELECT (SELECT count(*) FROM core.users WHERE org_id = $1::uuid),
			       (SELECT count(*) FROM core.directory_links WHERE source_id = $2::uuid),
			       (SELECT coalesce(min(remote_name), '') FROM core.directory_links WHERE source_id = $2::uuid)`,
			orgID, sourceID).Scan(&users, &links, &name); err != nil {
			t.Fatal(err)
		}
		return
	}
	email := "twice-" + suffix + "@example.test"
	sync(RemoteUser{ID: "r1", Email: email, Name: "First"}, RemoteUser{ID: "r1", Email: email, Name: "Second"})
	if u, l, name := state(); u != 1 || l != 1 || name != "Second" {
		t.Errorf("created: %d users, %d links, named %q; want one of each, named Second", u, l, name)
	}
	sync(RemoteUser{ID: "r1", Email: email, Name: "Third"}, RemoteUser{ID: "r1", Email: email, Name: "Fourth"})
	if u, l, name := state(); u != 1 || l != 1 || name != "Fourth" {
		t.Errorf("updated: %d users, %d links, named %q; want one of each, named Fourth", u, l, name)
	}
}

// Two directory entries with one address are two people claiming one account,
// and a source links a person once. It refuses the run rather than guess, and
// leaves nothing behind.
func TestTwoEntriesWithOneAddressRefuseTheRun(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	orgID, sourceID := fixture(t, pool)
	email := "shared-" + rnd(t) + "@example.test"
	remote := []RemoteUser{{ID: "r1", Email: email, Name: "One"}, {ID: "r2", Email: strings.ToUpper(email), Name: "Two"}}
	local, err := LoadLocal(ctx, pool, sourceID, orgID)
	if err != nil {
		t.Fatal(err)
	}
	err = Apply(ctx, pool, sourceID, orgID, BuildPlan(remote, local, "deactivate", 100))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), email) {
		t.Fatalf("two entries with one address answered %v; want it refused, naming the address", err)
	}
	var users, links int
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM core.users WHERE org_id = $1::uuid),
		       (SELECT count(*) FROM core.directory_links WHERE source_id = $2::uuid)`,
		orgID, sourceID).Scan(&users, &links); err != nil {
		t.Fatal(err)
	}
	if users != 0 || links != 0 {
		t.Errorf("a refused run left %d users and %d links", users, links)
	}
}

// Somebody with an account here before the sync began is adopted: the same
// account, switched on and linked, keeping how they sign in. Among others
// being created in the same run.
func TestAPersonWithAnAccountIsAdoptedAmongNewOnes(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	orgID, sourceID := fixture(t, pool)
	suffix := rnd(t)
	email := "Adopted-" + suffix + "@Example.test"
	var existing string
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, status, user_handle)
		VALUES ($1::uuid, $2, 'deactivated', sha256(convert_to($2, 'UTF8'))) RETURNING id::text`,
		orgID, email).Scan(&existing); err != nil {
		t.Fatal(err)
	}
	remote := []RemoteUser{{ID: "r1", Email: strings.ToLower(email), Name: "Adopted"},
		{ID: "r2", Email: "new-" + suffix + "@example.test", Name: "New"}}
	local, err := LoadLocal(ctx, pool, sourceID, orgID)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, pool, sourceID, orgID, BuildPlan(remote, local, "deactivate", 100)); err != nil {
		t.Fatal(err)
	}
	var linked, status string
	if err := pool.QueryRow(ctx, `
		SELECT l.user_id::text, u.status FROM core.directory_links l JOIN core.users u ON u.id = l.user_id
		WHERE l.source_id = $1::uuid AND l.remote_id = 'r1'`, sourceID).Scan(&linked, &status); err != nil {
		t.Fatal(err)
	}
	if linked != existing || status != "active" {
		t.Errorf("r1 links %s (%s); want the account they had, %s, active", linked, status, existing)
	}
}

// How long a directory of 100,000 takes. A benchmark, and against the
// throwaway database only: removing that many people takes longer than the
// sync, so it leaves them there.
//
//	SIGNARI_DESTRUCTIVE_TEST_DSN=… go test ./internal/directory -run '^$' -bench HundredThousand -benchtime 1x
func BenchmarkASyncOfAHundredThousand(b *testing.B) {
	dsn := os.Getenv("SIGNARI_DESTRUCTIVE_TEST_DSN")
	if dsn == "" {
		b.Skip("SIGNARI_DESTRUCTIVE_TEST_DSN not set")
	}
	pool, spent := countedPool(b, dsn)
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		suffix := fmt.Sprintf("%d", time.Now().UnixNano())
		var orgID, sourceID string
		if err := pool.QueryRow(ctx, `
			INSERT INTO core.organizations (instance_id, slug, display_name)
			SELECT id, $1, $1 FROM core.instances ORDER BY created_at LIMIT 1
			RETURNING id::text`, "bench-"+suffix).Scan(&orgID); err != nil {
			b.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `
			INSERT INTO core.directory_sources (org_id, kind, slug, display_name, credentials_enc, on_missing, dry_run)
			VALUES ($1::uuid, 'google', $2, 'bench', '\x00'::bytea, 'deactivate', false)
			RETURNING id::text`, orgID, "src-"+suffix).Scan(&sourceID); err != nil {
			b.Fatal(err)
		}
		remote := people(suffix, 0, 100000)
		run := func(step string) {
			local, err := LoadLocal(ctx, pool, sourceID, orgID)
			if err != nil {
				b.Fatal(err)
			}
			plan := BuildPlan(remote, local, "deactivate", 100)
			before, began := spent.n.Load(), time.Now()
			if err := Apply(ctx, pool, sourceID, orgID, plan); err != nil {
				b.Fatal(err)
			}
			b.Logf("%s: %v, %d statements", step, time.Since(began), spent.n.Load()-before)
		}
		run("creating 100,000")
		for j := range remote {
			remote[j].Name += " renamed"
		}
		run("updating 100,000")
	}
}
