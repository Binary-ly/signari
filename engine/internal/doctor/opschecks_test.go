package doctor

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The JSON report carries every finding with a lower-case severity and every
// check that ran (3.26), so a script can alert on it without parsing prose.
func TestTheReportIsJSONForAScript(t *testing.T) {
	r := &Report{}
	r.ran("one")
	r.add(Critical, "tenancy", "a table is open", "close it")
	r.add(Info, "database", "largest tables: x", "")
	raw, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Findings []struct{ Severity, Area, Summary, Fix string }
		Checked  []string
		Critical int
		Info     int
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, raw)
	}
	if got.Critical != 1 || got.Info != 1 || len(got.Findings) != 2 || got.Findings[0].Severity != "critical" ||
		got.Findings[0].Fix != "close it" || len(got.Checked) != 1 {
		t.Errorf("the JSON report is %s", raw)
	}
	empty, err := (&Report{}).JSON()
	if err != nil || !strings.Contains(string(empty), `"findings": []`) {
		t.Errorf("an empty report's findings are not an empty list: %s", empty)
	}
}

// A table that stops forcing row-level security, and sessions the janitor
// should have swept, are each reported. Inside a transaction on the test
// database that is always rolled back.
func TestATableLeftOpenAndAJanitorThatStoppedAreReported(t *testing.T) {
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
	run := func(check func(context.Context, *pgx.Conn, *Report) error) *Report {
		t.Helper()
		r := &Report{}
		if err := check(ctx, conn, r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := run(checkTenantIsolation); r.Count(Critical) != 0 {
		t.Fatalf("the test database already has an open table: %v", r.Findings)
	}

	if _, err := conn.Exec(ctx, `BEGIN`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(context.Background(), `ROLLBACK`) })
	if _, err := conn.Exec(ctx, `ALTER TABLE core.clients NO FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	if r := run(checkTenantIsolation); r.Count(Critical) != 1 || !strings.Contains(r.Findings[0].Summary, "clients") {
		t.Errorf("a table no longer forcing row-level security was reported as %v", r.Findings)
	}

	var org, user string
	if err := conn.QueryRow(ctx, `SELECT org_id::text, id::text FROM core.users LIMIT 1`).Scan(&org, &user); err != nil {
		t.Skipf("no user to hang a session off: %v", err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.sessions (sid, org_id, user_id, auth_time, not_after)
		VALUES ('doctor-backlog-' || gen_random_uuid(), $1::uuid, $2::uuid, now() - interval '3 hours',
		        now() - interval '2 hours')`, org, user); err != nil {
		t.Fatal(err)
	}
	if r := run(checkJanitorBacklog); r.Count(Warning) != 1 || !strings.Contains(r.Findings[0].Summary, "janitor has not run") {
		t.Errorf("a session two hours past its end, still live, was reported as %v", r.Findings)
	}
}
