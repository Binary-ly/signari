// Package migrate applies the engine's schema migrations and gates startup on a
// schema fingerprint.
//
// Two rules from ADR-004 and the research on why self-hosted upgrades fail:
//
//  1. Version skips are refused. Liquibase-style tools encode "how to get from N
//     to N+1" rather than "what the schema at N should be", so they cannot verify
//     current state, cannot repair drift, and cannot reason about a skip. We walk
//     every intermediate version internally instead.
//
//  2. The engine records a schema *fingerprint*, not just a counter, and refuses
//     to start when the live schema does not match what the binary expects.
//     Fail loudly at boot, not at 3am inside a query.
package migrate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/migrations"
)

// Tier separates migrations by the role they must run as. 0001 creates roles and
// schemas and therefore needs a superuser; everything after runs as signari_engine.
// Mixing them is how you get "permission denied to create role" halfway through
// a deploy.
type Tier int

const (
	// TierBootstrap is migration 0001 only: roles, schemas, grants. Superuser.
	TierBootstrap Tier = iota
	// TierCore is 0002 onward: tables, policies, views. Runs as signari_engine.
	TierCore
)

const bootstrapMaxVersion = 1

var filePattern = regexp.MustCompile(`^core/(\d{4})_([a-z0-9_]+)\.sql$`)

// Migration is one versioned SQL file embedded in the binary.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// noTransactionMarker, as a file's first line, runs it outside a transaction
// (3.01). Every file used to run in one, and CREATE INDEX CONCURRENTLY
// refuses to, so an index on a large table could only be built by locking it
// against writes for as long as the build took. Such a file may hold only
// concurrent index builds and drops, written to be run again: a failure part
// way leaves what it built, and the next run must not trip over it.
const noTransactionMarker = "-- signari:no-transaction"

var concurrentIndex = regexp.MustCompile(`(?is)^(?:CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY\s+IF\s+NOT\s+EXISTS\s+([a-z0-9_]+)\s+ON\s+core\.[a-z0-9_]+\b.*|DROP\s+INDEX\s+CONCURRENTLY\s+IF\s+EXISTS\s+core\.[a-z0-9_]+)$`)

// NoTransaction reports whether the migration runs outside a transaction.
func (m Migration) NoTransaction() bool {
	first, _, _ := strings.Cut(m.SQL, "\n")
	return strings.TrimSpace(first) == noTransactionMarker
}

// statements splits a no-transaction migration into the statements it runs,
// each with the index it builds ("" for a drop), refusing anything but a
// concurrent, repeatable index build or drop. A plain split on ";" is safe
// only because nothing else is allowed: no function body, no quoted string.
func (m Migration) statements() (stmts, builds []string, err error) {
	var body strings.Builder
	for _, line := range strings.Split(m.SQL, "\n") {
		if t := strings.TrimSpace(line); t == "" || strings.HasPrefix(t, "--") {
			continue
		}
		body.WriteString(line)
		body.WriteString("\n")
	}
	for _, s := range strings.Split(body.String(), ";") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		match := concurrentIndex.FindStringSubmatch(s)
		if match == nil {
			return nil, nil, fmt.Errorf("a %s migration may only build or drop indexes, "+
				"concurrently and repeatably (CREATE INDEX CONCURRENTLY IF NOT EXISTS name ON "+
				"core.table ..., DROP INDEX CONCURRENTLY IF EXISTS core.name); %.60q is neither",
				noTransactionMarker, s)
		}
		stmts = append(stmts, s)
		builds = append(builds, strings.ToLower(match[1]))
	}
	if len(stmts) == 0 {
		return nil, nil, fmt.Errorf("a %s migration holds no statement", noTransactionMarker)
	}
	return stmts, builds, nil
}

// Options bound what a migration may wait for.
type Options struct {
	// LockTimeout bounds each statement's wait for a lock. An ALTER TABLE
	// queued behind a long transaction makes every later query on that table
	// queue behind it, an outage that looks like a slow migration; failing
	// fast and running it again is the better trade. Zero means no bound.
	LockTimeout time.Duration
	// StatementTimeout bounds each statement. Zero means none: building an
	// index on a large table takes as long as it takes.
	StatementTimeout time.Duration
	// Waiting, when set, is called once if another `migrate` holds the lock.
	Waiting func()
}

// migrationLock is the session advisory lock Up holds, so that two
// deployments migrating at once take turns rather than racing for the same
// version (3.01). It was taken by nothing.
const migrationLock int64 = 0x7369676e6d696772 // "signmigr"

// Tier reports which role this migration must be applied as.
func (m Migration) Tier() Tier {
	if m.Version <= bootstrapMaxVersion {
		return TierBootstrap
	}
	return TierCore
}

// Load reads every embedded migration, sorted ascending by version.
func Load() ([]Migration, error) { return LoadFS(migrations.FS) }

// LoadFS is Load against an arbitrary filesystem. Split out so the contiguity and
// naming rules can be tested against synthetic migration sets rather than only
// against the real one -- a rule you cannot test a violation of is a rule you are
// trusting rather than enforcing.
//
// It rejects duplicate or non-contiguous version numbers at load time, because a
// gap in the sequence makes "walk N→N+1" meaningless.
func LoadFS(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.Glob(fsys, "core/*.sql")
	if err != nil {
		return nil, fmt.Errorf("globbing migrations: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no migrations found")
	}

	out := make([]Migration, 0, len(entries))
	for _, name := range entries {
		m := filePattern.FindStringSubmatch(name)
		if m == nil {
			return nil, fmt.Errorf("migration %q does not match NNNN_name.sql", name)
		}
		version, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, fmt.Errorf("migration %q has an unparseable version: %w", name, err)
		}
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("reading %q: %w", name, err)
		}
		mig := Migration{Version: version, Name: m[2], SQL: string(body)}
		if mig.NoTransaction() {
			if mig.Tier() == TierBootstrap {
				return nil, fmt.Errorf("migration %q: the bootstrap runs in one transaction", name)
			}
			if _, _, err := mig.statements(); err != nil {
				return nil, fmt.Errorf("migration %q: %w", name, err)
			}
		}
		if mig.CompatibleWithPrevious() {
			if err := checkCompatible(mig); err != nil {
				return nil, fmt.Errorf("migration %q: %w", name, err)
			}
		}
		out = append(out, mig)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })

	for i, m := range out {
		want := i + 1
		if m.Version != want {
			return nil, fmt.Errorf(
				"migration versions must be contiguous from 1: expected %04d, found %04d (%s)",
				want, m.Version, m.Name)
		}
	}
	return out, nil
}

// Applied returns the highest version recorded in core.schema_migrations.
// A missing ledger means version 0 -- nothing has been applied yet.
func Applied(ctx context.Context, conn *pgx.Conn) (int, error) {
	var exists bool
	err := conn.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'core' AND table_name = 'schema_migrations'
		)`).Scan(&exists)
	if err != nil {
		return 0, fmt.Errorf("checking for the migration ledger: %w", err)
	}
	if !exists {
		return 0, nil
	}

	var current int
	err = conn.QueryRow(ctx,
		`SELECT COALESCE(max(version), 0) FROM core.schema_migrations`).Scan(&current)
	if err != nil {
		return 0, fmt.Errorf("reading the migration ledger: %w", err)
	}
	return current, nil
}

// Up applies every pending migration in the given tier, one version at a time,
// each in its own transaction.
//
// `target` of 0 means "as far as this tier allows". Passing a target lower than
// the currently applied version is an error: we do not support downgrades, and
// pretending to would be worse than refusing.
func Up(ctx context.Context, conn *pgx.Conn, tier Tier, target int, opts Options) ([]Migration, error) {
	all, err := Load()
	if err != nil {
		return nil, err
	}
	return upFrom(ctx, conn, all, tier, target, opts)
}

// upFrom is Up over a given set of migrations, so a test can apply a set
// newer than the binary's own.
func upFrom(ctx context.Context, conn *pgx.Conn, all []Migration, tier Tier, target int, opts Options) ([]Migration, error) {
	// Before anything is applied: an older server failed part way, on the
	// first function it did not have.
	if err := checkServer(ctx, conn); err != nil {
		return nil, err
	}
	// One `migrate` at a time, and the ledger read once the lock is held: a
	// second run started alongside the first waits, then finds nothing left.
	//
	// Waited for by polling, between statements, never inside one. A session
	// blocked in pg_advisory_lock() holds a transaction open, and CREATE INDEX
	// CONCURRENTLY waits for every open transaction to end -- so the first run
	// building an index waited for the second, which waited for the first,
	// and the database broke the deadlock by failing the migration.
	if err := waitForMigrationLock(ctx, conn, opts.Waiting); err != nil {
		return nil, err
	}
	defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLock) }()

	current, err := Applied(ctx, conn)
	if err != nil {
		return nil, err
	}
	if target != 0 && target < current {
		return nil, fmt.Errorf(
			"refusing to downgrade: database is at version %d, target is %d", current, target)
	}

	var applied []Migration
	for _, m := range all {
		if m.Version <= current {
			continue
		}
		if m.Tier() != tier {
			// Stop rather than skip. Skipping would leave a hole in the ledger
			// and break the contiguity invariant Load() enforces.
			break
		}
		if target != 0 && m.Version > target {
			break
		}
		if err := applyOne(ctx, conn, m, tier, opts); err != nil {
			return applied, fmt.Errorf("migration %04d_%s: %w", m.Version, m.Name, err)
		}
		applied = append(applied, m)
	}
	return applied, nil
}

// lockPoll is how often a waiting run asks for the migration lock again.
const lockPoll = 250 * time.Millisecond

// waitForMigrationLock takes the migration lock, asking again every lockPoll
// while another run holds it, and calls waiting once if it had to.
func waitForMigrationLock(ctx context.Context, conn *pgx.Conn, waiting func()) error {
	for told := false; ; {
		var free bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, migrationLock).Scan(&free); err != nil {
			return fmt.Errorf("taking the migration lock: %w", err)
		}
		if free {
			return nil
		}
		if !told && waiting != nil {
			waiting()
		}
		told = true
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for the migration lock: %w", ctx.Err())
		case <-time.After(lockPoll):
		}
	}
}

// timeouts are the SET statements Options asks for, as Postgres reads them.
func (o Options) timeouts(local bool) []string {
	set := "SET "
	if local {
		set = "SET LOCAL "
	}
	var out []string
	if o.LockTimeout > 0 {
		out = append(out, fmt.Sprintf("%slock_timeout = '%dms'", set, o.LockTimeout.Milliseconds()))
	}
	if o.StatementTimeout > 0 {
		out = append(out, fmt.Sprintf("%sstatement_timeout = '%dms'", set, o.StatementTimeout.Milliseconds()))
	}
	return out
}

func applyOne(ctx context.Context, conn *pgx.Conn, m Migration, tier Tier, opts Options) error {
	if m.NoTransaction() {
		if err := applyOutsideTransaction(ctx, conn, m, opts); err != nil {
			return err
		}
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Core migrations run as signari_engine so that every object they create is
	// OWNED by signari_engine, regardless of which superuser ran the deploy. Object
	// ownership is what the whole GRANT boundary rests on, so it must not depend
	// on who happened to be holding the psql session.
	//
	// SET LOCAL, not SET: it reverts at commit and cannot leak to the next
	// transaction on a pooled connection.
	if tier == TierCore {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE signari_engine`); err != nil {
			return fmt.Errorf("assuming signari_engine: %w", err)
		}
	}
	for _, s := range opts.timeouts(true) {
		if _, err := tx.Exec(ctx, s); err != nil {
			return fmt.Errorf("%s: %w", s, err)
		}
	}

	if !m.NoTransaction() {
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			return err
		}
	}

	// The bootstrap tier creates the ledger it is about to write to, so record
	// it only once the table exists.
	fp, err := fingerprintTx(ctx, tx)
	if err != nil {
		return fmt.Errorf("fingerprinting: %w", err)
	}
	// With, once the migrations that add the columns have run, the PostgreSQL
	// version and the fingerprint scheme that computed it (0159, 0160), so it
	// is compared only like with like, and whether a binary built for the
	// version before may run against it (0160), which that binary cannot read
	// from a file it has never seen.
	has, err := ledgerColumns(ctx, tx)
	if err != nil {
		return fmt.Errorf("reading the ledger: %w", err)
	}
	switch {
	case has["fingerprint_scheme"] && has["compatible_with_previous"]:
		_, err = tx.Exec(ctx, `
			INSERT INTO core.schema_migrations (version, name, fingerprint, server_version_num,
			                                    fingerprint_scheme, compatible_with_previous)
			VALUES ($1, $2, $3, current_setting('server_version_num')::int, $4, $5)
			ON CONFLICT (version) DO UPDATE SET fingerprint = EXCLUDED.fingerprint,
			    server_version_num = EXCLUDED.server_version_num,
			    fingerprint_scheme = EXCLUDED.fingerprint_scheme,
			    compatible_with_previous = EXCLUDED.compatible_with_previous`,
			m.Version, m.Name, fp, fingerprintScheme, m.CompatibleWithPrevious())
	case has["server_version_num"]:
		_, err = tx.Exec(ctx, `
			INSERT INTO core.schema_migrations (version, name, fingerprint, server_version_num)
			VALUES ($1, $2, $3, current_setting('server_version_num')::int)
			ON CONFLICT (version) DO UPDATE SET fingerprint = EXCLUDED.fingerprint,
			    server_version_num = EXCLUDED.server_version_num`,
			m.Version, m.Name, fp)
	default:
		_, err = tx.Exec(ctx, `
			INSERT INTO core.schema_migrations (version, name, fingerprint)
			VALUES ($1, $2, $3)
			ON CONFLICT (version) DO UPDATE SET fingerprint = EXCLUDED.fingerprint`,
			m.Version, m.Name, fp)
	}
	if err != nil {
		return fmt.Errorf("recording in ledger: %w", err)
	}

	return tx.Commit(ctx)
}

// applyOutsideTransaction runs a no-transaction migration's statements one at
// a time, as signari_engine, then checks that every index it built is valid:
// a concurrent build that fails leaves an INVALID index behind, which IF NOT
// EXISTS would then skip forever. One found invalid is dropped and reported,
// so running the migration again builds it.
func applyOutsideTransaction(ctx context.Context, conn *pgx.Conn, m Migration, opts Options) error {
	stmts, builds, err := m.statements()
	if err != nil {
		return err
	}
	reset := context.WithoutCancel(ctx)
	if _, err := conn.Exec(ctx, `SET ROLE signari_engine`); err != nil {
		return fmt.Errorf("assuming signari_engine: %w", err)
	}
	defer func() { _, _ = conn.Exec(reset, `RESET ROLE`) }()
	for _, s := range opts.timeouts(false) {
		if _, err := conn.Exec(ctx, s); err != nil {
			return fmt.Errorf("%s: %w", s, err)
		}
	}
	defer func() {
		_, _ = conn.Exec(reset, `RESET lock_timeout`)
		_, _ = conn.Exec(reset, `RESET statement_timeout`)
	}()
	for i, s := range stmts {
		if _, err := conn.Exec(ctx, s); err != nil {
			return err
		}
		if builds[i] == "" {
			continue
		}
		var valid bool
		if err := conn.QueryRow(ctx, `SELECT indisvalid FROM pg_index
			WHERE indexrelid = to_regclass('core.' || $1)`, builds[i]).Scan(&valid); err != nil {
			return fmt.Errorf("checking index %s: %w", builds[i], err)
		}
		if !valid {
			if _, err := conn.Exec(ctx, `DROP INDEX CONCURRENTLY IF EXISTS core.`+builds[i]); err != nil {
				return fmt.Errorf("index %s is invalid and could not be dropped: %w", builds[i], err)
			}
			return fmt.Errorf("index %s was left invalid by an earlier build that failed; it has "+
				"been dropped, so running migrate up again builds it", builds[i])
		}
	}
	return nil
}

// ExpectedFingerprint is the fingerprint this binary was built against. It is
// computed by walking the embedded migrations against a scratch database during
// the build (scripts/build-release.sh), and pinned here. The zero value leaves
// the ledger comparison alone in force, which a hand change made together with
// a rewrite of the ledger row passes: fine in development, never in a release.
var ExpectedFingerprint string

// Verify gates engine startup. It refuses to start when the live schema does not
// match the binary's expectation, so a half-migrated or drifted database fails at
// boot with a clear message instead of producing wrong answers under load.
func Verify(ctx context.Context, conn *pgx.Conn) error {
	all, err := Load()
	if err != nil {
		return err
	}
	return verifyFor(ctx, conn, all[len(all)-1].Version)
}

// verifyFor is Verify for a binary whose latest migration is want.
func verifyFor(ctx context.Context, conn *pgx.Conn, want int) error {
	if err := checkServer(ctx, conn); err != nil {
		return err
	}
	current, err := Applied(ctx, conn)
	if err != nil {
		return err
	}
	if current < want {
		return fmt.Errorf(
			"schema version mismatch: database is at %d, this binary expects %d -- run `signari migrate up`",
			current, want)
	}
	// A database ahead of the binary is served when every migration since was
	// declared compatible with the version before it (3.03): the previous
	// release during a rolling upgrade, and the rollback afterwards.
	if current > want {
		if err := aheadIsCompatible(ctx, conn, want, current); err != nil {
			return err
		}
	}

	// The live schema against what the ledger recorded for the latest
	// migration. Unpinned, that is the whole fingerprint check: it catches a
	// hand change made since, and not one made together with a rewrite of the
	// ledger row, which only a pinned build can refuse. Before 3.04 an
	// unpinned build compared nothing. Pinned, it is how a database ahead of
	// the binary is compared, since the pin describes an earlier schema.
	if ExpectedFingerprint == "" || current > want {
		c, err := CompareLedger(ctx, conn)
		if err != nil {
			return fmt.Errorf("comparing the schema with its ledger: %w", err)
		}
		if c.Drifted() {
			return fmt.Errorf(
				"schema drift: the live schema (%s) is not what migration %d recorded (%s) -- "+
					"it has been changed by hand since",
				short(c.Live), c.Version, short(c.Recorded))
		}
	}
	if ExpectedFingerprint == "" {
		return nil
	}
	if current > want {
		// The pin against what the ledger recorded at this binary's own
		// version: the database passed through the schema the binary was
		// built for before the compatible migrations added to it.
		rec, why, err := recordedFingerprint(ctx, conn, want)
		if err != nil {
			return err
		}
		if why == "" && rec != ExpectedFingerprint {
			return fmt.Errorf(
				"schema fingerprint mismatch: migration %d recorded %s and this binary is pinned to %s -- "+
					"the database did not pass through the schema this binary was built for",
				want, short(rec), short(ExpectedFingerprint))
		}
		return nil
	}
	live, err := Fingerprint(ctx, conn)
	if err != nil {
		return err
	}
	if live != ExpectedFingerprint {
		return fmt.Errorf(
			"schema fingerprint mismatch: live %s, expected %s -- the database has drifted from what this binary was built against",
			short(live), short(ExpectedFingerprint))
	}
	return nil
}

// aheadIsCompatible refuses a database ahead of this binary unless the ledger
// records every migration after want as compatible with the version before.
func aheadIsCompatible(ctx context.Context, conn *pgx.Conn, want, current int) error {
	ahead := fmt.Sprintf("the database is at %d, ahead of this binary (%d)", current, want)
	deploy := fmt.Sprintf("deploy a binary built for %d, or restore the backup taken before the "+
		"upgrade (docs/upgrading.md)", current)
	has, err := ledgerColumns(ctx, conn)
	if err != nil {
		return err
	}
	if !has["compatible_with_previous"] {
		return fmt.Errorf("%s, and its ledger does not record which migrations an earlier binary "+
			"may run against -- %s", ahead, deploy)
	}
	var first int
	var name string
	err = conn.QueryRow(ctx, `
		SELECT version, name FROM core.schema_migrations
		WHERE version > $1 AND NOT compatible_with_previous ORDER BY version LIMIT 1`, want).
		Scan(&first, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%s, and migration %04d_%s is not compatible with an earlier binary -- %s",
		ahead, first, name, deploy)
}

// EarliestCompatible is the oldest binary version that may run against the
// database: the latest migration not declared compatible with the version
// before it. Equal to the database's version when the latest is not.
func EarliestCompatible(ctx context.Context, conn *pgx.Conn) (int, error) {
	current, err := Applied(ctx, conn)
	if err != nil || current == 0 {
		return current, err
	}
	has, err := ledgerColumns(ctx, conn)
	if err != nil || !has["compatible_with_previous"] {
		return current, err
	}
	var v int
	err = conn.QueryRow(ctx, `
		SELECT COALESCE(max(version), 1) FROM core.schema_migrations
		WHERE NOT compatible_with_previous`).Scan(&v)
	return v, err
}
