package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Fingerprint hashes the observable shape of schemas `core` and `core_v1`:
// every column, constraint and unique index, and the tenant boundary those
// tables rest on -- row-level security and whether it is forced, every policy,
// every view, every owner and grant, every function and trigger, and the
// attributes and memberships of the three signari roles.
//
// This is deliberately stronger than a version counter. Two databases can both
// claim version 7 and disagree, if someone hand-patched one of them. It covered
// only columns and constraints until 3.04, so a policy dropped by hand, FORCE
// ROW LEVEL SECURITY turned off, a view redefined or a grant to the console
// role left the digest unchanged: every change that breaks tenant isolation
// passed the gate that exists to notice hand changes.
func Fingerprint(ctx context.Context, conn *pgx.Conn) (string, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	return fingerprintTx(ctx, tx)
}

// signariRoles are the roles migration 0001 creates. Their attributes and
// memberships are part of the boundary: BYPASSRLS on the role that owns the
// views, or membership of the engine role granted to the console's, opens
// every tenant to the console.
const signariRoles = `('signari_engine', 'signari_admin', 'signari_maintenance')`

// roleSQL renders a role oid as its name, for the roles whose names are the
// same in every deployment; any other role, such as the superuser that ran
// the bootstrap, as <other>; and oid 0 as PUBLIC. A grant to an unexpected
// role still moves the digest, because it is still a row.
func roleSQL(oid string) string {
	return `COALESCE((SELECT CASE WHEN rolname LIKE 'signari\_%' OR rolname LIKE 'pg\_%' ` +
		`THEN rolname ELSE '<other>' END FROM pg_roles WHERE oid = ` + oid + `), 'PUBLIC')`
}

// fingerprintSections each return one line per object. The lines are sorted
// in Go rather than by ORDER BY, whose order follows the database's
// collation and would give two deployments of one schema two digests.
var fingerprintSections = []struct{ name, query string }{
	{"columns", `
		SELECT format('column %s.%s|%s|%s|%s|%s', c.relname, a.attname,
		       format_type(a.atttypid, a.atttypmod), a.attnotnull,
		       COALESCE(pg_get_expr(d.adbin, d.adrelid), ''), a.attgenerated)
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		WHERE n.nspname = 'core' AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped`},
	{"constraints", `
		SELECT format('constraint %s.%s|%s', c.relname, con.conname, pg_get_constraintdef(con.oid))
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'core' AND c.relkind IN ('r', 'p')`},
	// Unique indexes only: one refuses writes, so adding or dropping it changes
	// what the engine does. An index added for speed changes nothing, and
	// refusing to start over one would punish an operator for tuning.
	{"unique indexes", `
		SELECT format('index %s|%s', pg_get_indexdef(i.indexrelid), i.indisvalid)
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'core' AND i.indisunique`},
	{"row-level security", `
		SELECT format('rls %s|%s|%s', c.relname, c.relrowsecurity, c.relforcerowsecurity)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'core' AND c.relkind IN ('r', 'p')`},
	{"policies", `
		SELECT format('policy %s.%s|%s|%s|%s|%s|%s', c.relname, p.polname, p.polcmd, p.polpermissive,
		       (SELECT string_agg(` + roleSQL("u.role_oid") + `, ',' ORDER BY ` + roleSQL("u.role_oid") + ` COLLATE "C")
		          FROM unnest(p.polroles) AS u(role_oid)),
		       COALESCE(pg_get_expr(p.polqual, p.polrelid), ''),
		       COALESCE(pg_get_expr(p.polwithcheck, p.polrelid), ''))
		FROM pg_policy p
		JOIN pg_class c ON c.oid = p.polrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname IN ('core', 'core_v1')`},
	{"views", `
		SELECT format('view %s.%s|%s|%s', n.nspname, c.relname,
		       COALESCE(array_to_string(c.reloptions, ','), ''), pg_get_viewdef(c.oid))
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname IN ('core', 'core_v1') AND c.relkind IN ('v', 'm')`},
	// A view runs with its owner's privileges, so its owner decides what it
	// can see.
	{"owners", `
		SELECT format('owner %s.%s|%s|%s', n.nspname, c.relname, c.relkind, ` + roleSQL("c.relowner") + `)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname IN ('core', 'core_v1') AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')`},
	{"grants", `
		SELECT format('grant %s.%s|%s|%s|%s', n.nspname, c.relname, ` + roleSQL("g.grantee") + `,
		       g.privilege_type, g.is_grantable)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		CROSS JOIN LATERAL aclexplode(c.relacl) g
		WHERE n.nspname IN ('core', 'core_v1') AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')`},
	{"column grants", `
		SELECT format('column-grant %s.%s.%s|%s|%s|%s', n.nspname, c.relname, a.attname,
		       ` + roleSQL("g.grantee") + `, g.privilege_type, g.is_grantable)
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		CROSS JOIN LATERAL aclexplode(a.attacl) g
		WHERE n.nspname IN ('core', 'core_v1') AND a.attnum > 0 AND NOT a.attisdropped`},
	{"schemas", `
		SELECT format('schema %s|%s', n.nspname, ` + roleSQL("n.nspowner") + `)
		FROM pg_namespace n WHERE n.nspname IN ('core', 'core_v1')
		UNION ALL
		SELECT format('schema-grant %s|%s|%s|%s', n.nspname, ` + roleSQL("g.grantee") + `,
		       g.privilege_type, g.is_grantable)
		FROM pg_namespace n
		CROSS JOIN LATERAL aclexplode(n.nspacl) g
		WHERE n.nspname IN ('core', 'core_v1')`},
	// Every policy calls core.is_engine(), so its body is part of every policy.
	{"functions", `
		SELECT format('function %s.%s(%s)|%s|%s|%s|%s|%s|%s', n.nspname, p.proname,
		       pg_get_function_identity_arguments(p.oid), pg_get_function_result(p.oid),
		       ` + roleSQL("p.proowner") + `, p.prosecdef, p.provolatile,
		       COALESCE(array_to_string(p.proconfig, ','), ''), md5(p.prosrc))
		FROM pg_proc p
		JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname IN ('core', 'core_v1')
		UNION ALL
		SELECT format('function-grant %s.%s(%s)|%s|%s|%s', n.nspname, p.proname,
		       pg_get_function_identity_arguments(p.oid), ` + roleSQL("g.grantee") + `,
		       g.privilege_type, g.is_grantable)
		FROM pg_proc p
		JOIN pg_namespace n ON n.oid = p.pronamespace
		CROSS JOIN LATERAL aclexplode(p.proacl) g
		WHERE n.nspname IN ('core', 'core_v1')`},
	{"triggers", `
		SELECT format('trigger %s|%s', t.tgenabled, pg_get_triggerdef(t.oid))
		FROM pg_trigger t
		JOIN pg_class c ON c.oid = t.tgrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'core' AND NOT t.tgisinternal`},
	{"roles", `
		SELECT format('role %s|super=%s|bypassrls=%s|createrole=%s|createdb=%s|replication=%s',
		       rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication)
		FROM pg_roles WHERE rolname IN ` + signariRoles},
	{"memberships", `
		SELECT format('member %s|%s|admin=%s', m.rolname, ` + roleSQL("a.roleid") + `, a.admin_option)
		FROM pg_auth_members a
		JOIN pg_roles m ON m.oid = a.member
		WHERE m.rolname IN ` + signariRoles},
}

func fingerprintTx(ctx context.Context, tx pgx.Tx) (string, error) {
	// With only pg_catalog on the search path, every name in core renders
	// schema-qualified. The migrations set `search_path = core, public` for
	// the session, so the ledger's fingerprints were computed with names
	// unqualified and no live read ever matched them.
	var saved string
	if err := tx.QueryRow(ctx, `SELECT current_setting('search_path')`).Scan(&saved); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('search_path', 'pg_catalog, pg_temp', true)`); err != nil {
		return "", err
	}
	defer func() {
		_, _ = tx.Exec(context.WithoutCancel(ctx), `SELECT set_config('search_path', $1, true)`, saved)
	}()

	h := sha256.New()
	for _, s := range fingerprintSections {
		rows, err := tx.Query(ctx, s.query)
		if err != nil {
			return "", fmt.Errorf("fingerprinting %s: %w", s.name, err)
		}
		lines, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return "", fmt.Errorf("fingerprinting %s: %w", s.name, err)
		}
		sort.Strings(lines)
		for _, l := range lines {
			h.Write([]byte(l))
			h.Write([]byte{'\n'})
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// LedgerCheck compares the live schema with what the ledger recorded when the
// latest migration was applied.
type LedgerCheck struct {
	Version  int
	Recorded string
	Live     string
	// Comparable is false when the ledger row cannot say anything: it was
	// written before the ledger recorded the PostgreSQL version (0159), by an
	// earlier fingerprint, or under another major version of PostgreSQL,
	// whose catalogue may render the same schema differently.
	Comparable bool
	Reason     string
}

// Drifted reports a comparable ledger row that the live schema no longer
// matches.
func (c LedgerCheck) Drifted() bool { return c.Comparable && c.Recorded != c.Live }

// CompareLedger reads the latest ledger row and the live fingerprint.
func CompareLedger(ctx context.Context, conn *pgx.Conn) (LedgerCheck, error) {
	var c LedgerCheck
	hasColumn, err := ledgerRecordsServerVersion(ctx, conn)
	if err != nil {
		return c, err
	}
	if !hasColumn {
		c.Reason = "the ledger predates migration 0159, which records the PostgreSQL version"
		return c, nil
	}
	var recordedNum *int
	var liveNum int
	err = conn.QueryRow(ctx, `
		SELECT version, fingerprint, server_version_num, current_setting('server_version_num')::int
		FROM core.schema_migrations ORDER BY version DESC LIMIT 1`).
		Scan(&c.Version, &c.Recorded, &recordedNum, &liveNum)
	if errors.Is(err, pgx.ErrNoRows) {
		c.Reason = "nothing has been applied"
		return c, nil
	}
	if err != nil {
		return c, err
	}
	switch {
	case recordedNum == nil:
		c.Reason = fmt.Sprintf("migration %d was recorded before the ledger recorded the PostgreSQL "+
			"version, by an earlier fingerprint", c.Version)
		return c, nil
	case *recordedNum/10000 != liveNum/10000:
		c.Reason = fmt.Sprintf("migration %d was recorded under PostgreSQL %d and this is %d, whose "+
			"catalogue may render the same schema differently; the comparison resumes with the "+
			"next migration", c.Version, *recordedNum/10000, liveNum/10000)
		return c, nil
	}
	if c.Live, err = Fingerprint(ctx, conn); err != nil {
		return c, err
	}
	c.Comparable = true
	return c, nil
}

// ledgerRecordsServerVersion reports whether migration 0159 has added the
// column, so a migration applied before it can still be recorded.
func ledgerRecordsServerVersion(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
		               WHERE attrelid = to_regclass('core.schema_migrations')
		                 AND attname = 'server_version_num' AND NOT attisdropped)`).Scan(&ok)
	return ok, err
}

// short abbreviates a digest for a message.
func short(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return strings.TrimSpace(fp)
}
