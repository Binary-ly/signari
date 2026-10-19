package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// A group with no verb, and no command at all, print the usage rather than
// guessing; a command that needs the database says so before trying to reach
// one; a flag the binary does not know is refused rather than ignored.
func TestTheDispatchRefusesWhatItCannotRun(t *testing.T) {
	t.Setenv("SIGNARI_DSN", "")
	for _, c := range []struct {
		args []string
		says string
	}{
		{nil, "no command given"},
		{[]string{"client"}, "no command given"},
		{[]string{"group", "list"}, "no -dsn given"},
		{[]string{"theme", "check", "-no-such-flag"}, "no-such-flag"},
	} {
		err := run(c.args)
		if err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("signari %s: %v, want an error saying %q", strings.Join(c.args, " "), err, c.says)
		}
	}
}

// An ejected page checks clean; the same page with its CSRF token removed is
// refused by name; ejecting again leaves the operator's edit alone unless told
// to overwrite it, and the overwritten page checks clean again. All without a
// database, because a pipeline checks a theme where there is none.
func TestAThemeIsEjectedCheckedAndRefusedWithoutADatabase(t *testing.T) {
	t.Setenv("SIGNARI_DSN", "")
	dir := t.TempDir()
	page := filepath.Join(dir, "login.html")

	if err := run([]string{"theme", "eject", "-theme-dir", dir, "-theme-page", "login"}); err != nil {
		t.Fatalf("eject: %v", err)
	}
	if err := run([]string{"theme", "check", "-theme-dir", dir}); err != nil {
		t.Fatalf("the page as shipped was refused: %v", err)
	}

	built, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	const csrf = `<input type="hidden" name="{{.CSRFField}}" value="{{.CSRF}}">`
	if !strings.Contains(string(built), csrf) {
		t.Fatalf("login.html no longer carries %s; this test needs the field it removes", csrf)
	}
	edited := strings.Replace(string(built), csrf, "", 1)
	if err := os.WriteFile(page, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"theme", "check", "-theme-dir", dir}); err == nil {
		t.Fatal("a login page with no CSRF token was accepted")
	}

	if err := run([]string{"theme", "eject", "-theme-dir", dir, "-theme-page", "login"}); err != nil {
		t.Fatalf("eject again: %v", err)
	}
	if now, _ := os.ReadFile(page); string(now) != edited {
		t.Fatal("ejecting again overwrote the operator's edit without -theme-force")
	}
	if err := run([]string{"theme", "eject", "-theme-dir", dir, "-theme-page", "login", "-theme-force"}); err != nil {
		t.Fatalf("eject -theme-force: %v", err)
	}
	if err := run([]string{"theme", "check", "-theme-dir", dir}); err != nil {
		t.Errorf("the page restored by -theme-force was refused: %v", err)
	}

	if err := run([]string{"theme", "eject", "-theme-dir", dir, "-theme-page", "no-such-page"}); err == nil {
		t.Error("ejecting a page that does not exist succeeded")
	}
}

// A key set published to a whole federation carries public members only; a
// private member of any JWA key type is refused before it can be signed into
// the Entity Configuration.
func TestAFederationKeySetCarryingPrivateMaterialIsRefused(t *testing.T) {
	public := map[string]any{"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "BBBB"}
	for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		leaked := map[string]any{"kty": "EC", member: "secret"}
		raw, _ := json.Marshal(map[string]any{"keys": []any{public, leaked}})
		err := refuseNonPublicJWKS(raw)
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%q", member)) {
			t.Errorf("a key carrying %q: %v", member, err)
		}
	}
	for name, raw := range map[string]string{
		"no keys":     `{"keys":[]}`,
		"not JSON":    `{"keys":`,
		"no keys key": `{}`,
	} {
		if err := refuseNonPublicJWKS(json.RawMessage(raw)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	raw, _ := json.Marshal(map[string]any{"keys": []any{public}})
	if err := refuseNonPublicJWKS(raw); err != nil {
		t.Errorf("a public key set was refused: %v", err)
	}
}

// `user create` and `client create` act in the organisation -org names, and
// refuse to guess when it names none and there are several. Both took the
// oldest organisation whatever -org said (2.16).
func TestCreateCommandsActInTheOrganisationNamed(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(ctx) }()
	var second string
	if err := db.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name)
		           VALUES ('https://cli-org-' || gen_random_uuid() || '.test', 'CLI org test') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'c' || substr(gen_random_uuid()::text, 1, 8), 'Second' FROM i RETURNING id::text`).
		Scan(&second); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UnixNano()
	email := fmt.Sprintf("cli-org-%d@example.test", stamp)
	client := fmt.Sprintf("cli-org-%d", stamp)
	t.Cleanup(func() {
		c := context.Background()
		_, _ = db.Exec(c, `DELETE FROM core.users WHERE email = $1`, email)
		_, _ = db.Exec(c, `DELETE FROM core.clients WHERE client_id = $1`, client)
	})

	if err := run([]string{"user", "create", "-dsn", dsn, "-org", second, "-email", email,
		"-password", "a-long-enough-password-for-the-cli-test-2026"}); err != nil {
		t.Fatalf("user create -org: %v", err)
	}
	if err := run([]string{"client", "create", "-dsn", dsn, "-org", second, "-client-id", client,
		"-redirect", "https://cli-org.test/cb"}); err != nil {
		t.Fatalf("client create -org: %v", err)
	}
	var userOrg, clientOrg string
	if err := db.QueryRow(ctx, `SELECT org_id::text FROM core.users WHERE email = $1`, email).Scan(&userOrg); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT org_id::text FROM core.clients WHERE client_id = $1`, client).Scan(&clientOrg); err != nil {
		t.Fatal(err)
	}
	if userOrg != second || clientOrg != second {
		t.Errorf("created the user in %s and the client in %s, not the organisation named, %s",
			userOrg, clientOrg, second)
	}

	// The test database holds many organisations, so no -org is ambiguous.
	err = run([]string{"user", "create", "-dsn", dsn, "-email", "x" + email, "-password", "another-long-password-2026"})
	if err == nil || !strings.Contains(err.Error(), "give -org") {
		t.Errorf("user create with no -org among several organisations answered %v", err)
	}
	if err := run([]string{"client", "create", "-dsn", dsn, "-org", "not-a-uuid", "-client-id", client + "x",
		"-redirect", "https://cli-org.test/cb"}); err == nil {
		t.Error("an -org that is not an organisation id was accepted")
	}
}

// The whole CLI write path as an operator meets it: `group create` through the
// dispatch moves core.config_version and leaves one admin.cli_command record
// naming the command and its flags, never their values; the same command
// failing leaves none; a command that only reads leaves none. The pieces are
// tested in store; this proves run() puts them on the path every command takes.
func TestACLIWriteMovesTheVersionAndIsRecordedOnce(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(ctx) }()

	var org string
	if err := db.QueryRow(ctx, `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&org); err != nil {
		t.Skipf("no organisation to create a group in: %v", err)
	}
	group := fmt.Sprintf("clitest-%d", time.Now().UnixNano())
	_, _ = db.Exec(ctx, `DELETE FROM core.groups WHERE name LIKE 'clitest-%' AND created_at < now() - interval '2 minutes'`)
	t.Cleanup(func() { _, _ = db.Exec(ctx, `DELETE FROM core.groups WHERE name = $1`, group) })

	version := func() int64 {
		t.Helper()
		var v int64
		if err := db.QueryRow(ctx, `SELECT version FROM core.config_version`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	var since time.Time
	if err := db.QueryRow(ctx, `SELECT now()`).Scan(&since); err != nil {
		t.Fatal(err)
	}
	records := func(command string) []string {
		t.Helper()
		rows, err := db.Query(ctx, `
			SELECT detail::text FROM core.audit_events
			 WHERE event_type = 'admin.cli_command' AND detail->>'command' = $1
			   AND org_id = $2 AND occurred_at >= $3`, command, org, since)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err != nil {
				t.Fatal(err)
			}
			// Only this test's: another package may run group create meanwhile.
			if strings.Contains(d, `"group"`) && strings.Contains(d, `"dsn"`) {
				out = append(out, d)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	before := version()
	if err := run([]string{"group", "create", "-dsn", dsn, "-org", org, "-group", group}); err != nil {
		t.Fatalf("group create: %v", err)
	}
	if after := version(); after <= before {
		t.Errorf("group create left core.config_version at %d, so a conditional write read before it "+
			"would still apply", after)
	}
	got := records("group create")
	if len(got) != 1 {
		t.Fatalf("%d admin.cli_command records for group create, want 1: %q", len(got), got)
	}
	for _, value := range []string{group, org, dsn} {
		if strings.Contains(got[0], value) {
			t.Errorf("the record carries the value %q of a flag it was given: %s", value, got[0])
		}
	}

	// The same group again is refused, and a refused command recorded nothing.
	if err := run([]string{"group", "create", "-dsn", dsn, "-org", org, "-group", group}); err == nil {
		t.Fatal("creating the same group twice succeeded")
	}
	if n := len(records("group create")); n != 1 {
		t.Errorf("%d records after a refused group create, want still 1", n)
	}

	// A command that only reads changes nothing and is not recorded.
	if err := run([]string{"group", "list", "-dsn", dsn, "-org", org, "-group", group}); err != nil {
		t.Fatalf("group list: %v", err)
	}
	if n := len(records("group list")); n != 0 {
		t.Errorf("group list, which reads only, was recorded %d time(s)", n)
	}
}
