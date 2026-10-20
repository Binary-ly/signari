package migrate

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A database restored the way the runbook restores one matches its own
// ledger (3.03). pg_dump writes every constraint, policy, view and default as
// PostgreSQL renders it and the restore parses that text again, so anything
// whose rendering does not survive the round trip moves the fingerprint, and
// the engine refuses to start on the restored database as drift. A CHECK
// written with BETWEEN did exactly that (0161). Every line that differs is
// named.
func TestARestoredDatabaseMatchesItsLedger(t *testing.T) {
	dump, derr := exec.LookPath("pg_dump")
	restore, rerr := exec.LookPath("pg_restore")
	if derr != nil || rerr != nil {
		t.Skip("pg_dump and pg_restore are not on PATH")
	}
	saved := ExpectedFingerprint
	t.Cleanup(func() { ExpectedFingerprint = saved })
	ExpectedFingerprint = ""

	ctx := context.Background()
	connect, name := scratchDBAt(t)
	conn := connect()
	if _, err := Up(ctx, conn, TierBootstrap, 0, Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := Up(ctx, conn, TierCore, 0, Options{}); err != nil {
		t.Fatal(err)
	}
	conn = connect()
	var serverMajor int
	if err := conn.QueryRow(ctx, `SELECT current_setting('server_version_num')::int / 10000`).Scan(&serverMajor); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(dump, "--version").Output(); err == nil {
		if m := regexp.MustCompile(`\) (\d+)`).FindSubmatch(out); m != nil {
			if v, _ := strconv.Atoi(string(m[1])); v < serverMajor {
				t.Skipf("pg_dump %d cannot dump a PostgreSQL %d server", v, serverMajor)
			}
		}
	}

	restoredConnect, restored := scratchDBAt(t)
	file := t.TempDir() + "/round-trip.dump"
	if out, err := exec.Command(dump, "--format=custom", "--clean", "--if-exists",
		"--dbname="+dsnFor(t, name), "--file="+file).CombinedOutput(); err != nil {
		t.Fatalf("pg_dump: %v\n%s", err, out)
	}
	if out, err := exec.Command(restore, "--dbname="+dsnFor(t, restored), "--clean", "--if-exists",
		file).CombinedOutput(); err != nil {
		t.Fatalf("pg_restore: %v\n%s", err, out)
	}

	back := restoredConnect()
	original, again := linesOf(t, conn), linesOf(t, back)
	for l := range original {
		if !again[l] {
			t.Errorf("changed by the round trip, before: %.240s", l)
		}
	}
	for l := range again {
		if !original[l] {
			t.Errorf("changed by the round trip, after:  %.240s", l)
		}
	}
	if err := Verify(ctx, back); err != nil {
		t.Errorf("the restored database does not pass verify: %v", err)
	}
}

func dsnFor(t *testing.T, database string) string {
	t.Helper()
	u, err := url.Parse(os.Getenv("SIGNARI_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + database
	// pg_dump refuses the parameters only pgx reads.
	q := u.Query()
	for k := range q {
		if k == "default_query_exec_mode" || strings.HasSuffix(k, "_cache_capacity") || strings.HasPrefix(k, "pool_") {
			q.Del(k)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func linesOf(t *testing.T, conn *pgx.Conn) map[string]bool {
	t.Helper()
	ctx := context.Background()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('search_path', 'pg_catalog, pg_temp', true)`); err != nil {
		t.Fatal(err)
	}
	lines, err := fingerprintLines(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, l := range lines {
		out[l] = true
	}
	return out
}
