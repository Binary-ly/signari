package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/config"
)

// A command and a configuration apply to the same thing at once, both commit
// (0307), staged as internal/adminapi's lock-order tests are. A third
// transaction holds what the command needs, so the command waits holding
// whatever it took first; the apply is started and waits behind it; then the
// third lets go. Taken in opposite orders, the command and the apply each hold
// what the other wants, and PostgreSQL ends one of them a second later with
// 40P01. In one order, the second waits for the first to commit.
//
// The commands are run as an operator runs them, through run. Every step waits
// until pg_blocking_pids says the one before it is in place; the apply's
// backend is found by a name its pool alone carries.

// lockStage is the test database's address, a pool that holds and watches, and
// a pool for the apply whose connections carry name.
func lockStage(t *testing.T) (dsn string, observer, applier *pgxpool.Pool, name string) {
	t.Helper()
	dsn = os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	observer, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(observer.Close)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	name = fmt.Sprintf("signari-lockorder-cli-%d", time.Now().UnixNano())
	cfg.ConnConfig.RuntimeParams["application_name"] = name
	if applier, err = pgxpool.NewWithConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(applier.Close)
	return dsn, observer, applier, name
}

// holdRow runs lock in a transaction of its own and keeps it open until
// release. The pid is the holder's backend.
func holdRow(t *testing.T, pool *pgxpool.Pool, lock string, args ...any) (release func(), pid int) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	release = func() { _ = tx.Rollback(context.Background()) }
	t.Cleanup(release)
	if _, err := tx.Exec(ctx, lock, args...); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return release, pid
}

// pollUntil polls until cond holds, failing with what it was waiting for after
// thirty seconds: in a full run another package may hold the version's row for
// a while, and a step waits for it first.
func pollUntil(t *testing.T, what string, cond func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		ok, err := cond()
		if err != nil {
			t.Fatalf("waiting for %s: %v", what, err)
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never happened", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waiterOn finds the backend waiting on holder, which holds a row nothing but
// the test touches.
func waiterOn(observer *pgxpool.Pool, holder int, pid *int) func() (bool, error) {
	return func() (bool, error) {
		err := observer.QueryRow(context.Background(), `
			SELECT pid FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)) LIMIT 1`,
			holder).Scan(pid)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return err == nil, err
	}
}

// namedWaiterOn says whether a backend of the named pool waits on blocker.
func namedWaiterOn(observer *pgxpool.Pool, name string, blocker int) func() (bool, error) {
	return func() (bool, error) {
		var yes bool
		err := observer.QueryRow(context.Background(), `
			SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			                WHERE application_name = $1 AND $2::int = ANY(pg_blocking_pids(pid)))`,
			name, blocker).Scan(&yes)
		return yes, err
	}
}

// arrivedWithin is what ch delivers, failing if nothing comes in thirty seconds.
func arrivedWithin(t *testing.T, what string, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(30 * time.Second):
		t.Fatalf("%s never finished", what)
		return nil
	}
}

// applyIn plans f for org and applies it in a transaction of the applier's,
// rolled back after: what is staged is the apply's locks, not its result.
func applyIn(pool *pgxpool.Pool, org string, f *config.File, prune bool) error {
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	plan, err := config.BuildPlan(ctx, tx, org, f, prune)
	if err != nil {
		return err
	}
	return config.Apply(ctx, tx, org, f, plan)
}

// `signari apply -prune` with a file that leaves a provider out, which switches
// it off, and `signari idp trust-mfa` on that provider, at once. The command's
// statement locked the provider's row and then went for the version's, which
// the apply had taken first and held while it waited for the provider -- the
// failure the shared test database showed three times in two days.
func TestAPruningApplyAndACommandOnTheProviderItSwitchesOffBothCommit(t *testing.T) {
	dsn, observer, applier, name := lockStage(t)
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	org, _ := newLifecycleOrg(t, db)
	slug := fmt.Sprintf("lockorder-%d", time.Now().UnixNano())
	if _, err := db.Exec(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id)
		VALUES ($1::uuid, $2, 'lock order', 'oidc', 'signari')`, org, slug); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM core.identity_providers WHERE slug = $1`, slug)
	})

	release, holder := holdRow(t, observer,
		`SELECT 1 FROM core.identity_providers WHERE slug = $1 FOR UPDATE`, slug)
	cliDone := make(chan error, 1)
	go func() {
		cliDone <- run([]string{"idp", "trust-mfa", "-dsn", dsn, "-slug", slug, "-upstream-amr", "mfa"})
	}()
	var cliPID int
	pollUntil(t, "`idp trust-mfa` to wait for the held provider", waiterOn(observer, holder, &cliPID))

	applyDone := make(chan error, 1)
	go func() { applyDone <- applyIn(applier, org, &config.File{}, true) }()
	pollUntil(t, "the pruning apply to wait behind the command", namedWaiterOn(observer, name, cliPID))
	release()

	if err := arrivedWithin(t, "`idp trust-mfa`", cliDone); err != nil {
		t.Errorf("`idp trust-mfa`: %v", err)
	}
	if err := arrivedWithin(t, "the pruning apply", applyDone); err != nil {
		t.Errorf("the pruning apply: %v", err)
	}
	var amr []string
	if err := db.QueryRow(ctx, `SELECT mfa_amr FROM core.identity_providers WHERE slug = $1`, slug).
		Scan(&amr); err != nil {
		t.Fatal(err)
	}
	if len(amr) != 1 || amr[0] != "mfa" {
		t.Errorf("the provider trusts %v after the command, want [mfa]", amr)
	}
}

// `signari instance org-status` and an apply that adds a group to the same
// organisation, at once. The command reads the organisation's row FOR UPDATE
// before it writes, and a read fires no trigger, so without beginEdit it held
// the row and went for the version's at its write; the apply takes the
// version's row first and then needs the organisation's, to check the new
// group's reference to it.
func TestAnOrganisationStatusChangeAndAnApplyIntoItBothCommit(t *testing.T) {
	dsn, observer, applier, name := lockStage(t)
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	org, _ := newLifecycleOrg(t, db)
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM core.groups WHERE org_id = $1::uuid`, org)
	})

	release, holder := holdRow(t, observer,
		`SELECT 1 FROM core.organizations WHERE id = $1::uuid FOR UPDATE`, org)
	cliDone := make(chan error, 1)
	go func() {
		cliDone <- run([]string{"instance", "org-status", "-dsn", dsn, "-org", org, "-status", "suspended"})
	}()
	var cliPID int
	pollUntil(t, "`instance org-status` to wait for the held organisation", waiterOn(observer, holder, &cliPID))

	group := &config.File{Groups: []config.Group{{Name: fmt.Sprintf("lockorder-%d", time.Now().UnixNano())}}}
	applyDone := make(chan error, 1)
	go func() { applyDone <- applyIn(applier, org, group, false) }()
	pollUntil(t, "the apply to wait behind the command", namedWaiterOn(observer, name, cliPID))
	release()

	if err := arrivedWithin(t, "`instance org-status`", cliDone); err != nil {
		t.Errorf("`instance org-status`: %v", err)
	}
	if err := arrivedWithin(t, "the apply", applyDone); err != nil {
		t.Errorf("the apply: %v", err)
	}
	var status string
	if err := db.QueryRow(ctx, `SELECT status FROM core.organizations WHERE id = $1::uuid`, org).
		Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "suspended" {
		t.Errorf("the organisation is %s after the command, want suspended", status)
	}
}
