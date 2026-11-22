package migrate

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
)

func loadWith(t *testing.T, second string, bootstrapMarked bool) error {
	t.Helper()
	first := "SELECT 1;\n"
	if bootstrapMarked {
		first = compatibleMarker + "\n" + first
	}
	_, err := LoadFS(fstest.MapFS{
		"core/0001_bootstrap.sql": {Data: []byte(first)},
		"core/0002_second.sql":    {Data: []byte("-- 0002_second.sql\n" + compatibleMarker + "\n\n" + second)},
	})
	return err
}

// A migration declared compatible with the binary before it may only add
// (3.03). The declaration is what lets the earlier binary serve the database,
// so a declaration on a migration that changes what that binary relies on
// would let it run against a schema it breaks on.
func TestAMigrationMarkedCompatibleMayOnlyAdd(t *testing.T) {
	adds := `
SET search_path = core, public;
CREATE TABLE core.widgets (
    id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id  uuid NOT NULL REFERENCES core.organizations (id),
    label   text NOT NULL CHECK (label <> ';')
);
ALTER TABLE core.widgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.widgets FORCE ROW LEVEL SECURITY;
CREATE POLICY widgets_org_isolation ON core.widgets
    USING (core.is_engine() OR org_id = core.current_org_id());
CREATE UNIQUE INDEX widgets_label ON core.widgets (org_id, label);
CREATE TRIGGER widgets_cli_bumps_version AFTER INSERT OR UPDATE OR DELETE ON core.widgets
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_on_cli_write();
INSERT INTO core.widgets (org_id, label) SELECT id, 'first; of many' FROM core.organizations;
ALTER TABLE core.users ADD COLUMN nickname text;
ALTER TABLE core.users ADD COLUMN IF NOT EXISTS shoe_size integer NOT NULL DEFAULT 0;
CREATE INDEX users_nickname ON core.users (nickname);
CREATE FUNCTION core.widget_count() RETURNS bigint LANGUAGE sql STABLE AS $$
    SELECT count(*) FROM core.widgets; -- a semicolon inside the body
$$;
CREATE VIEW core_v1.widgets AS SELECT id, org_id, label FROM core.widgets;
COMMENT ON TABLE core.widgets IS 'Things; with a semicolon.';
GRANT SELECT ON core_v1.widgets TO signari_admin;
`
	if err := loadWith(t, adds, false); err != nil {
		t.Fatalf("a migration that only adds was refused: %v", err)
	}

	for _, c := range []struct{ name, sql string }{
		{"a column dropped", `ALTER TABLE core.users DROP COLUMN locale;`},
		{"a column made NOT NULL", `ALTER TABLE core.users ALTER COLUMN locale SET NOT NULL;`},
		{"a NOT NULL column with no default", `ALTER TABLE core.users ADD COLUMN tier text NOT NULL;`},
		{"two clauses in one ALTER", `ALTER TABLE core.users ADD COLUMN a text, DROP COLUMN locale;`},
		{"a constraint on a table it writes", `ALTER TABLE core.users ADD CONSTRAINT x CHECK (email <> '');`},
		{"a unique index on a table it writes", `CREATE UNIQUE INDEX users_x ON core.users (locale);`},
		{"a policy on a table it reads", `CREATE POLICY p ON core.users USING (true);`},
		{"a trigger on a table it writes", `CREATE TRIGGER t BEFORE INSERT ON core.users FOR EACH ROW EXECUTE FUNCTION core.f();`},
		{"a view it reads replaced", `CREATE OR REPLACE VIEW core_v1.users AS SELECT 1 AS id;`},
		{"a function it calls replaced", `CREATE OR REPLACE FUNCTION core.is_engine() RETURNS boolean LANGUAGE sql AS $$ SELECT true $$;`},
		{"rows it reads written", `INSERT INTO core.clients (client_id) VALUES ('x');`},
		{"rows updated", `UPDATE core.users SET locale = 'en';`},
		{"rows deleted", `DELETE FROM core.sessions;`},
		{"an arbitrary block", `DO $$ BEGIN PERFORM 1; END $$;`},
		{"a grant revoked", `REVOKE SELECT ON core_v1.users FROM signari_admin;`},
		{"a table dropped", `DROP TABLE core.sessions;`},
		{"an index dropped", `DROP INDEX core.users_org_email_key;`},
	} {
		err := loadWith(t, c.sql, false)
		if err == nil {
			t.Errorf("%s: accepted under %s", c.name, compatibleMarker)
			continue
		}
		if !strings.Contains(err.Error(), compatibleMarker) {
			t.Errorf("%s: refused without naming the marker: %v", c.name, err)
		}
	}
	if err := loadWith(t, "SELECT 1;", true); err == nil {
		t.Error("a bootstrap marked compatible was accepted")
	}
}

// The release before serves a database a compatible migration has moved
// ahead of it (3.03). Every binary used to refuse every database but its own
// version, so the previous release crash-looped through a rolling upgrade and
// could not be rolled back to. Against a database migrated from empty, then
// moved one migration ahead: served unpinned and pinned to its own version's
// fingerprint; refused when pinned to another, when changed by hand, and once
// a migration that is not compatible lands.
func TestThePreviousBinaryServesADatabaseOneCompatibleMigrationAhead(t *testing.T) {
	saved := ExpectedFingerprint
	t.Cleanup(func() { ExpectedFingerprint = saved })
	ExpectedFingerprint = ""

	connect := scratchDB(t)
	ctx := context.Background()
	conn := connect()
	all, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := upFrom(ctx, conn, all, TierBootstrap, 0, Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := upFrom(ctx, conn, all, TierCore, 0, Options{}); err != nil {
		t.Fatal(err)
	}
	conn = connect()
	v := all[len(all)-1].Version
	atV, err := Fingerprint(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}

	added := Migration{Version: v + 1, Name: "compat_probe", SQL: compatibleMarker + `
CREATE TABLE core.compat_probe (id integer PRIMARY KEY);
ALTER TABLE core.users ADD COLUMN compat_probe text;`}
	if err := checkCompatible(added); err != nil {
		t.Fatal(err)
	}
	if _, err := upFrom(ctx, connect(), append(append([]Migration{}, all...), added), TierCore, 0, Options{}); err != nil {
		t.Fatal(err)
	}

	if err := verifyFor(ctx, conn, v); err != nil {
		t.Fatalf("unpinned, the binary for %d refused a database one compatible migration ahead: %v", v, err)
	}
	ExpectedFingerprint = atV
	if err := verifyFor(ctx, conn, v); err != nil {
		t.Fatalf("pinned to its own version, the binary for %d refused: %v", v, err)
	}
	ExpectedFingerprint = strings.Repeat("0", 64)
	if err := verifyFor(ctx, conn, v); err == nil || !strings.Contains(err.Error(), "did not pass through") {
		t.Errorf("pinned to a schema the database never had, verify said %v", err)
	}
	ExpectedFingerprint = ""
	// The probe is compatible, and so may be the newest real migrations under
	// it: the oldest binary is the one before the newest that is not.
	want := v
	for i := len(all) - 1; i > 0 && all[i].CompatibleWithPrevious(); i-- {
		want = all[i-1].Version
	}
	if got, err := EarliestCompatible(ctx, conn); err != nil || got != want {
		t.Errorf("EarliestCompatible = %d (%v), want %d", got, err, want)
	}

	if _, err := conn.Exec(ctx, `ALTER TABLE core.users NO FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	if err := verifyFor(ctx, conn, v); err == nil || !strings.Contains(err.Error(), "schema drift") {
		t.Errorf("a hand change on a database ahead of the binary: verify said %v", err)
	}
	if _, err := conn.Exec(ctx, `ALTER TABLE core.users FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}

	breaking := Migration{Version: v + 2, Name: "compat_probe_dropped",
		SQL: `ALTER TABLE core.users DROP COLUMN compat_probe;`}
	if _, err := upFrom(ctx, connect(), append(append([]Migration{}, all...), added, breaking),
		TierCore, 0, Options{}); err != nil {
		t.Fatal(err)
	}
	err = verifyFor(ctx, conn, v)
	if want := fmt.Sprintf("%04d_compat_probe_dropped is not compatible", v+2); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("a database ahead by a migration that is not compatible: verify said %v, want %q", err, want)
	}
	if got, err := EarliestCompatible(ctx, conn); err != nil || got != v+2 {
		t.Errorf("EarliestCompatible = %d (%v), want %d", got, err, v+2)
	}
}
