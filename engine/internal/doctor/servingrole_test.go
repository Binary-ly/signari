package doctor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A connection that signs in as, or acts as, a role row-level security does
// not bind is critical; signari_engine, which the forced policies bind, is not.
func TestARoleRowSecurityDoesNotBindIsCritical(t *testing.T) {
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
		}
		// serve decides on the same answer.
		if role, unbound := UnboundRole(c.session, c.current); unbound != c.critical ||
			(unbound && !strings.Contains(r.Findings[0].Summary, role.Name)) {
			t.Errorf("%s: UnboundRole says %v (%+v), the finding %v", c.why, unbound, role, r.Findings)
		}
	}
	if (Role{Name: "x", BypassRLS: true}).Kind() != "a role with BYPASSRLS" || super.Kind() != "a superuser" {
		t.Error("a role's kind is named wrongly")
	}
}

// Against the test database, the finding is exactly what pg_roles says of the
// role the DSN signs in as: a superuser DSN, the suite's usual one, is
// reported, and anything else that neither is nor acts as one is not.
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
	var unbound bool
	if err := conn.QueryRow(ctx, `SELECT bool_or(rolsuper OR rolbypassrls) FROM pg_catalog.pg_roles
		WHERE rolname IN (session_user, current_user)`).Scan(&unbound); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	if err := checkServingRole(ctx, conn, r); err != nil {
		t.Fatal(err)
	}
	if got := r.Count(Critical) == 1; got != unbound {
		t.Errorf("the DSN's role bypasses row-level security: %v; reported critical: %v (%v)", unbound, got, r.Findings)
	}
	if len(r.Checked) != 1 || r.Checked[0] != "database role" {
		t.Errorf("the check did not say it ran: %v", r.Checked)
	}
}
