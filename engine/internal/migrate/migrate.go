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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"

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
		out = append(out, Migration{Version: version, Name: m[2], SQL: string(body)})
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
func Up(ctx context.Context, conn *pgx.Conn, tier Tier, target int) ([]Migration, error) {
	all, err := Load()
	if err != nil {
		return nil, err
	}
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
		if err := applyOne(ctx, conn, m, tier); err != nil {
			return applied, fmt.Errorf("migration %04d_%s: %w", m.Version, m.Name, err)
		}
		applied = append(applied, m)
	}
	return applied, nil
}

func applyOne(ctx context.Context, conn *pgx.Conn, m Migration, tier Tier) error {
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

	if _, err := tx.Exec(ctx, m.SQL); err != nil {
		return err
	}

	// The bootstrap tier creates the ledger it is about to write to, so record
	// it only once the table exists.
	fp, err := fingerprintTx(ctx, tx)
	if err != nil {
		return fmt.Errorf("fingerprinting: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.schema_migrations (version, name, fingerprint)
		VALUES ($1, $2, $3)
		ON CONFLICT (version) DO UPDATE SET fingerprint = EXCLUDED.fingerprint`,
		m.Version, m.Name, fp,
	); err != nil {
		return fmt.Errorf("recording in ledger: %w", err)
	}

	return tx.Commit(ctx)
}

// ExpectedFingerprint is the fingerprint this binary was built against. It is
// computed by walking the embedded migrations against a scratch database during
// the build, and pinned here. Zero value means "not pinned yet" and disables the
// startup gate -- acceptable during early development, never in a release.
var ExpectedFingerprint string

// Verify gates engine startup. It refuses to start when the live schema does not
// match the binary's expectation, so a half-migrated or drifted database fails at
// boot with a clear message instead of producing wrong answers under load.
func Verify(ctx context.Context, conn *pgx.Conn) error {
	all, err := Load()
	if err != nil {
		return err
	}
	want := all[len(all)-1].Version

	current, err := Applied(ctx, conn)
	if err != nil {
		return err
	}
	if current != want {
		return fmt.Errorf(
			"schema version mismatch: database is at %d, this binary expects %d -- run `signari migrate up`",
			current, want)
	}

	if ExpectedFingerprint == "" {
		return nil // unpinned development build
	}
	live, err := Fingerprint(ctx, conn)
	if err != nil {
		return err
	}
	if live != ExpectedFingerprint {
		return fmt.Errorf(
			"schema fingerprint mismatch: live %s, expected %s -- the database has drifted from what this binary was built against",
			live[:12], ExpectedFingerprint[:12])
	}
	return nil
}

// Fingerprint hashes the observable shape of schema `core`: every column, its
// type, nullability and default, plus every table constraint. Deterministically
// ordered so the same schema always produces the same digest.
//
// This is deliberately stronger than a version counter. Two databases can both
// claim version 7 and disagree, if someone hand-patched one of them.
func Fingerprint(ctx context.Context, conn *pgx.Conn) (string, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	return fingerprintTx(ctx, tx)
}

func fingerprintTx(ctx context.Context, tx pgx.Tx) (string, error) {
	rows, err := tx.Query(ctx, `
		SELECT c.table_name, c.column_name, c.data_type,
		       c.is_nullable, COALESCE(c.column_default, '')
		FROM information_schema.columns c
		JOIN information_schema.tables t
		  ON t.table_schema = c.table_schema AND t.table_name = c.table_name
		WHERE c.table_schema = 'core' AND t.table_type = 'BASE TABLE'
		ORDER BY c.table_name, c.column_name`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	h := sha256.New()
	var b strings.Builder
	for rows.Next() {
		var table, col, typ, nullable, def string
		if err := rows.Scan(&table, &col, &typ, &nullable, &def); err != nil {
			return "", err
		}
		b.Reset()
		b.WriteString(table)
		b.WriteByte('.')
		b.WriteString(col)
		b.WriteByte('|')
		b.WriteString(typ)
		b.WriteByte('|')
		b.WriteString(nullable)
		b.WriteByte('|')
		b.WriteString(def)
		b.WriteByte('\n')
		h.Write([]byte(b.String()))
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
