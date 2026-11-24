package doctor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A connection that signs in as, acts as, or may SET ROLE to a superuser or a
// BYPASSRLS role is critical: a compromised engine would hold powers it never
// needs. signari_engine, which reads every organisation by design and has no
// such power, is not.
func TestAPrivilegedServingRoleIsCritical(t *testing.T) {
	engine := Role{Name: "signari_engine"}
	super := Role{Name: "postgres", Super: true}
	for _, c := range []struct {
		why              string
		session, current Role
		critical         bool
	}{
		{"the engine's own role", engine, engine, false},
		{"a superuser", super, super, true},
		// RESET ROLE is one statement away, and an injection could send it.
		{"a superuser acting as the engine", super, engine, true},
		{"the engine acting as a BYPASSRLS role", engine, Role{Name: "signari_maintenance", BypassRLS: true}, true},
		{"a BYPASSRLS login", Role{Name: "ops", BypassRLS: true}, Role{Name: "ops", BypassRLS: true}, true},
		// SET ROLE postgres is one statement away too.
		{"the engine able to become a superuser", Role{Name: "signari_engine", Reaches: "postgres", ReachesSuper: true},
			engine, true},
		{"the engine able to become a BYPASSRLS role", Role{Name: "signari_engine", Reaches: "signari_maintenance"},
			engine, true},
	} {
		r := findingsFor(t, func(r *Report) { reportServingRole(r, c.session, c.current) })
		if got := r.Count(Critical) == 1; got != c.critical {
			t.Errorf("%s: critical = %v, want %v (%v)", c.why, got, c.critical, r.Findings)
			continue
		}
		if len(r.Findings) > 1 {
			t.Errorf("%s: %d findings for one connection, want at most one", c.why, len(r.Findings))
		}
		if c.critical {
			f := r.Findings[0]
			for _, want := range []string{"signari_engine", "signari setup", "migrate bootstrap"} {
				if !strings.Contains(f.Fix, want) {
					t.Errorf("%s: the fix does not name %q: %s", c.why, want, f.Fix)
				}
			}
			if strings.Contains(f.Summary, "row-level security") || !strings.Contains(f.Summary, "never needs") {
				t.Errorf("%s: the finding gives the wrong reason: %s", c.why, f.Summary)
			}
		}
		// serve decides on the same answer.
		if role, privileged := PrivilegedRole(c.session, c.current); privileged != c.critical ||
			(privileged && !strings.Contains(r.Findings[0].Summary, role.Name)) {
			t.Errorf("%s: PrivilegedRole says %v (%+v), the finding %v", c.why, privileged, role, r.Findings)
		}
	}
	for role, kind := range map[Role]string{
		{Name: "x", BypassRLS: true}: "a role with BYPASSRLS",
		super:                        "a superuser",
		{Name: "e", Reaches: "postgres", ReachesSuper: true}: "a role that may SET ROLE to postgres, a superuser",
		{Name: "e", Reaches: "m"}:                            "a role that may SET ROLE to m, which has BYPASSRLS",
	} {
		if got := role.Kind(); got != kind {
			t.Errorf("%+v is named %q, want %q", role, got, kind)
		}
	}
}

// Against the test database, the finding is exactly what pg_roles says of the
// role the DSN signs in as: a superuser DSN, the suite's usual one, is
// reported; a login role that may SET ROLE to it is reported too, as the
// role it may become; and signari_engine, with no such membership, is not.
func TestTheServingRoleIsReadFromTheConnection(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	var privileged bool
	if err := conn.QueryRow(ctx, `SELECT bool_or(rolsuper OR rolbypassrls) FROM pg_catalog.pg_roles
		WHERE rolname IN (session_user, current_user)`).Scan(&privileged); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	if err := checkServingRole(ctx, conn, r); err != nil {
		t.Fatal(err)
	}
	if got := r.Count(Critical) == 1; got != privileged {
		t.Errorf("the DSN's role is privileged: %v; reported critical: %v (%v)", privileged, got, r.Findings)
	}
	if len(r.Checked) != 1 || r.Checked[0] != "database role" {
		t.Errorf("the check did not say it ran: %v", r.Checked)
	}
	if !privileged {
		return
	}
	// A login role granted membership in a superuser, with SET, signs in as
	// nothing privileged and may become it with one statement.
	const su, reacher = "signari_doctor_super_test", "signari_doctor_setrole_test"
	for _, r := range []string{reacher, su} {
		_, _ = conn.Exec(ctx, "DROP ROLE IF EXISTS "+r)
	}
	if _, err := conn.Exec(ctx, "CREATE ROLE "+su+" NOLOGIN SUPERUSER"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "CREATE ROLE "+reacher+" LOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, r := range []string{reacher, su} {
			_, _ = conn.Exec(context.Background(), "DROP ROLE IF EXISTS "+r)
		}
	})
	if _, err := conn.Exec(ctx, "GRANT "+su+" TO "+reacher+" WITH INHERIT FALSE, SET TRUE"); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.User = reacher
	rc, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Skipf("the cluster does not let %s sign in: %v", reacher, err)
	}
	defer func() { _ = rc.Close(ctx) }()
	session, current, err := ConnectionRoles(ctx, rc)
	if err != nil {
		t.Fatal(err)
	}
	role, priv := PrivilegedRole(session, current)
	if !priv || role.Reaches != su || !role.ReachesSuper || session.Super || session.BypassRLS {
		t.Errorf("a role that may SET ROLE to %s reads as %+v / %+v (privileged %v)", su, session, current, priv)
	}
	if _, err := conn.Exec(ctx, "REVOKE "+su+" FROM "+reacher); err != nil {
		t.Fatal(err)
	}
	if session, current, err = ConnectionRoles(ctx, rc); err != nil {
		t.Fatal(err)
	}
	if _, priv := PrivilegedRole(session, current); priv {
		t.Errorf("once the membership is revoked, %s still reads as privileged: %+v", reacher, session)
	}
}
