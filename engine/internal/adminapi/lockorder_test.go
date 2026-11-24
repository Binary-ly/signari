package adminapi

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
)

// A CLI write and an unconditional write through this API, at once, both
// commit (4.25). The CLI takes the configuration version's row before its
// first statement does anything (migration 0307's trigger runs before the
// statement) and the audit chain's lock after; this API took the chain lock
// inside fn and the row at the end, and the two deadlocked -- seen as a 500 in
// the full parallel run.
//
// Staged: the CLI side holds the row, the API write is started, and only then
// does the CLI side audit. Under the old order the API write had the chain
// lock by then and was waiting for the row.
func TestACLIWriteAndAnAPIWriteTogetherBothCommit(t *testing.T) {
	s, pool := newTestServer(t)
	ctx := context.Background()
	org := anyOrgID(t, s)

	cli, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Rollback(ctx) }()
	if _, err := cli.Exec(ctx, `SELECT set_config('signari.cli_write', 'on', true)`); err != nil {
		t.Fatal(err)
	}
	// Any statement on a core table moves the version under the CLI setting;
	// this one changes no row.
	if _, err := cli.Exec(ctx, `UPDATE core.organizations SET display_name = display_name WHERE false`); err != nil {
		t.Fatal(err)
	}

	ran := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := s.mutate(ctx, func(tx pgx.Tx) error {
			close(ran)
			return audit.Write(ctx, tx, audit.Event{Type: "admin.webauthn_policy_set", OrgID: org,
				Detail: map[string]any{"test": "lock order"}})
		})
		done <- err
	}()
	select {
	case <-ran:
		// The old order: fn ran while the CLI side held the row.
	case <-time.After(500 * time.Millisecond):
		// Waiting for the row before fn, as it should.
	}

	if err := audit.Write(ctx, cli, audit.Event{Type: "admin.webauthn_policy_set", OrgID: org,
		Detail: map[string]any{"test": "lock order", "via": "cli"}}); err != nil {
		t.Fatalf("the CLI side's audit record: %v", err)
	}
	if err := cli.Commit(ctx); err != nil {
		t.Fatalf("the CLI side's commit: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the API write: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the API write never finished")
	}
}

// The tests below are a CLI write and an API write to the same thing at once,
// staged so that each side has taken its first lock before the other asks for
// it, which is the moment the two orders meet (0307). A third transaction holds
// what the CLI's statement needs, so the statement waits holding whatever it
// took before; the API write is started and waits behind it; then the third
// lets go. Taken in opposite orders, the CLI and the API each hold what the
// other wants, and PostgreSQL ends one of them a second later with 40P01. In
// one order, the second simply waits for the first to commit, and both do.
//
// Nothing here is timing: every step waits until pg_blocking_pids says the one
// before it is in place, and the API's backends are found by a name of their
// own, never by guessing which of the suite's other connections is which.

// lockOrderServer is newTestServer over a pool whose connections carry a name
// no other test's do, so the API's backend can be told apart.
func lockOrderServer(t *testing.T) (s *Server, observer *pgxpool.Pool, name string) {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	name = fmt.Sprintf("signari-lockorder-%d", time.Now().UnixNano())
	cfg.ConnConfig.RuntimeParams["application_name"] = name
	named, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(named.Close)
	s, err = New(named, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), testToken)
	if err != nil {
		t.Fatal(err)
	}
	s.arrivals, s.perToken = nil, nil
	if observer, err = pgxpool.New(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(observer.Close)
	return s, observer, name
}

// cliSession is a connection marked as cmd/signari marks its own.
func cliSession(t *testing.T) (*pgx.Conn, int) {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, os.Getenv("SIGNARI_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	if _, err := c.Exec(ctx, `SELECT set_config('signari.cli_write', 'on', false)`); err != nil {
		t.Fatal(err)
	}
	return c, int(c.PgConn().PID())
}

// holdWith runs lock in a transaction of its own and keeps it open; the
// returned release rolls it back. The pid is the holder's backend.
func holdWith(t *testing.T, pool *pgxpool.Pool, lock string, args ...any) (release func(), pid int) {
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

// waitFor polls until cond holds, failing with what it was waiting for after
// thirty seconds: in a full run another package's transaction may hold the
// version's row for a while, and a step waits for it first.
func waitFor(t *testing.T, what string, cond func() (bool, error)) {
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

// waitsOn says whether backend waiter is waiting for a lock blocker holds, or
// is ahead of it for.
func waitsOn(observer *pgxpool.Pool, waiter, blocker int) func() (bool, error) {
	return func() (bool, error) {
		var yes bool
		err := observer.QueryRow(context.Background(),
			`SELECT $2::int = ANY(pg_blocking_pids($1::int))`, waiter, blocker).Scan(&yes)
		return yes, err
	}
}

// namedWaitsOn says whether a backend of the named pool is waiting on blocker.
func namedWaitsOn(observer *pgxpool.Pool, name string, blocker int) func() (bool, error) {
	return func() (bool, error) {
		var yes bool
		err := observer.QueryRow(context.Background(), `
			SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			                WHERE application_name = $1 AND $2::int = ANY(pg_blocking_pids(pid)))`,
			name, blocker).Scan(&yes)
		return yes, err
	}
}

// within is what ch delivers, failing if it delivers nothing in thirty seconds.
func within[T any](t *testing.T, what string, ch <-chan T) T {
	t.Helper()
	var v T
	select {
	case v = <-ch:
	case <-time.After(30 * time.Second):
		t.Fatalf("%s never finished", what)
	}
	return v
}

func newLockOrderClient(t *testing.T, s *Server, org string) string {
	t.Helper()
	id := fmt.Sprintf("lockorder-%d", time.Now().UnixNano())
	if _, err := s.db.Exec(context.Background(), `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash, enabled)
		VALUES ($1, $2::uuid, 'lock order', 'confidential', 'x', true)`, id, org); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
	})
	return id
}

// `signari client …` and PATCH /admin/clients/{id} on one client at once. The
// CLI's statement locked the client's row and, after it, went for the version's
// row, which the API had taken first and held while it waited for the client.
func TestACLIWriteAndAnAPIWriteToOneClientBothCommit(t *testing.T) {
	s, observer, name := lockOrderServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	clientID := newLockOrderClient(t, s, org)

	release, holder := holdWith(t, observer,
		`SELECT 1 FROM core.clients WHERE client_id = $1 FOR UPDATE`, clientID)
	cli, cliPID := cliSession(t)
	cliDone := make(chan error, 1)
	go func() {
		_, err := cli.Exec(ctx, `UPDATE core.clients SET enabled = false WHERE client_id = $1`, clientID)
		cliDone <- err
	}()
	waitFor(t, "the CLI's write to wait for the held client", waitsOn(observer, cliPID, holder))

	req := adminReq(t, http.MethodPatch, "/admin/clients/"+clientID, `{"enabled":true}`, "")
	routes := s.Routes()
	apiDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		apiDone <- rec
	}()
	waitFor(t, "the API's write to wait behind the CLI's", namedWaitsOn(observer, name, cliPID))
	release()

	if err := within(t, "the CLI's write", cliDone); err != nil {
		t.Errorf("the CLI's write: %v", err)
	}
	if rec := within(t, "the API's write", apiDone); rec.Code != http.StatusOK {
		t.Errorf("the API's write answered %d %s (a deadlock is a 500, and the server log names it)",
			rec.Code, rec.Body.String())
	}
	var enabled bool
	if err := observer.QueryRow(ctx, `SELECT enabled FROM core.clients WHERE client_id = $1`,
		clientID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Error("the API's write, which waited for the CLI's, is not the one that stands")
	}
}

// `signari user create` and POST /admin/users in one organisation at once, two
// different people. Nothing is shared but the organisation's identifier lock,
// which core.users' trigger takes for each new person (0255): the CLI's
// statement took it and then the version's row, and the API the other way.
func TestACLIPersonAndAnAPIPersonInOneOrganisationBothCommit(t *testing.T) {
	s, observer, name := lockOrderServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE org_id = $1::uuid`, org)
	})
	n := time.Now().UnixNano()

	release, holder := holdWith(t, observer,
		`SELECT pg_advisory_xact_lock(hashtextextended('signari.identifier:' || $1::uuid, 0))`, org)
	cli, cliPID := cliSession(t)
	handle := make([]byte, 64)
	if _, err := rand.Read(handle); err != nil {
		t.Fatal(err)
	}
	cliDone := make(chan error, 1)
	go func() {
		// The statement `signari user create` makes.
		_, err := cli.Exec(ctx, `INSERT INTO core.users (org_id, user_handle, email) VALUES ($1, $2, $3)`,
			org, handle, fmt.Sprintf("cli-%d@example.test", n))
		cliDone <- err
	}()
	waitFor(t, "the CLI's person to wait for the organisation's identifier lock", waitsOn(observer, cliPID, holder))

	req := adminReq(t, http.MethodPost, "/admin/users",
		fmt.Sprintf(`{"org_id":%q,"email":"api-%d@example.test"}`, org, n), "")
	routes := s.Routes()
	apiDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		apiDone <- rec
	}()
	waitFor(t, "the API's person to wait behind the CLI's", namedWaitsOn(observer, name, cliPID))
	release()

	if err := within(t, "the CLI's person", cliDone); err != nil {
		t.Errorf("the CLI's person: %v", err)
	}
	if rec := within(t, "the API's person", apiDone); rec.Code != http.StatusCreated {
		t.Errorf("the API's person answered %d %s (a deadlock is a 500, and the server log names it)",
			rec.Code, rec.Body.String())
	}
}

// A CLI transaction that records before it writes, as `signari proxy-host` and
// `signari export-subject` do, and an API write that records, at once. The CLI
// took the audit chain's lock first and the version's row at its write; the API
// takes the row and then the chain's lock. core.audit_append now takes the row
// first in a CLI session (0307).
func TestACLITransactionThatRecordsFirstAndAnAPIWriteBothCommit(t *testing.T) {
	s, observer, name := lockOrderServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)

	cli, cliPID := cliSession(t)
	tx, err := cli.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := audit.Write(ctx, tx, audit.Event{Type: "admin.webauthn_policy_set", OrgID: org,
		Detail: map[string]any{"test": "lock order", "via": "cli"}}); err != nil {
		t.Fatal(err)
	}

	apiDone := make(chan error, 1)
	go func() {
		_, err := s.mutate(ctx, func(tx pgx.Tx) error {
			return audit.Write(ctx, tx, audit.Event{Type: "admin.webauthn_policy_set", OrgID: org,
				Detail: map[string]any{"test": "lock order"}})
		})
		apiDone <- err
	}()
	waitFor(t, "the API's write to wait behind the CLI's transaction", namedWaitsOn(observer, name, cliPID))

	if _, err := tx.Exec(ctx, `UPDATE core.organizations SET display_name = display_name WHERE id = $1::uuid`,
		org); err != nil {
		t.Errorf("the CLI's write after its record: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Errorf("the CLI's commit: %v", err)
	}
	if err := within(t, "the API's write", apiDone); err != nil {
		t.Errorf("the API's write: %v", err)
	}
}
