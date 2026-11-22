package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// The switches the engine read and nothing could set (2.29): an outpost, a
// prompt and a remote-access connection could not be taken out of service, a
// connection's guacd parameters could not be set, and a registration token
// could only be waited out. Each command writes the column its reader checks.
func TestEverySwitchTheEngineReadsHasACommand(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) }) // after the deletes below

	var org string
	if err := db.QueryRow(ctx, `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&org); err != nil {
		t.Skipf("no organisation: %v", err)
	}
	n := fmt.Sprint(time.Now().UnixNano())
	hash := func() []byte {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return b
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO core.outposts (org_id, name, kind, token_hash) VALUES ($1::uuid, $2, 'ldap', $3)`,
			[]any{org, "op-" + n, hash()}},
		{`INSERT INTO core.prompts (org_id, slug, title) VALUES ($1::uuid, $2, 'Terms')`, []any{org, "pr-" + n}},
		{`INSERT INTO core.rac_connections (org_id, slug, display_name, protocol, hostname, port)
			VALUES ($1::uuid, $2, 'desk', 'rdp', 'desk.internal', 3389)`, []any{org, "rac-" + n}},
		{`INSERT INTO core.registration_tokens (org_id, name, token_hash) VALUES ($1::uuid, $2, $3)`,
			[]any{org, "reg-" + n, hash()}},
		{`INSERT INTO core.registration_tokens (org_id, name, token_hash) VALUES ($1::uuid, $2, $3)`,
			[]any{org, "twin-" + n, hash()}},
		{`INSERT INTO core.registration_tokens (org_id, name, token_hash) VALUES ($1::uuid, $2, $3)`,
			[]any{org, "twin-" + n, hash()}},
	} {
		if _, err := db.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = db.Exec(ctx, `DELETE FROM core.outposts WHERE name = $1`, "op-"+n)
		_, _ = db.Exec(ctx, `DELETE FROM core.prompts WHERE slug = $1`, "pr-"+n)
		_, _ = db.Exec(ctx, `DELETE FROM core.rac_connections WHERE slug = $1`, "rac-"+n)
		_, _ = db.Exec(ctx, `DELETE FROM core.registration_tokens WHERE name LIKE '%-' || $1`, n)
	})
	cli := func(args ...string) error {
		return run(append([]string{args[0], args[1], "-dsn", dsn, "-org", org}, args[2:]...))
	}
	value := func(sql string, args ...any) string {
		t.Helper()
		var v string
		if err := db.QueryRow(ctx, sql, args...).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	for _, step := range []struct {
		args []string
		read string
		key  string
		want string
	}{
		{[]string{"outpost", "disable", "-name", "op-" + n}, `SELECT enabled::text FROM core.outposts WHERE name = $1`, "op-" + n, "false"},
		{[]string{"outpost", "enable", "-name", "op-" + n}, `SELECT enabled::text FROM core.outposts WHERE name = $1`, "op-" + n, "true"},
		{[]string{"prompt", "disable", "-slug", "pr-" + n}, `SELECT enabled::text FROM core.prompts WHERE slug = $1`, "pr-" + n, "false"},
		{[]string{"rac", "disable", "-slug", "rac-" + n}, `SELECT enabled::text FROM core.rac_connections WHERE slug = $1`, "rac-" + n, "false"},
		{[]string{"rac", "set-parameters", "-slug", "rac-" + n, "-rac-params", "security=nla, ignore-cert=true"},
			`SELECT parameters::text FROM core.rac_connections WHERE slug = $1`, "rac-" + n, `{"security": "nla", "ignore-cert": "true"}`},
		{[]string{"rac", "set-parameters", "-slug", "rac-" + n},
			`SELECT parameters::text FROM core.rac_connections WHERE slug = $1`, "rac-" + n, `{}`},
		{[]string{"registration", "revoke", "-name", "reg-" + n},
			`SELECT (revoked_at IS NOT NULL)::text FROM core.registration_tokens WHERE name = $1`, "reg-" + n, "true"},
	} {
		if err := cli(step.args...); err != nil {
			t.Fatalf("%s: %v", strings.Join(step.args, " "), err)
		}
		if got := value(step.read, step.key); got != step.want {
			t.Errorf("after %s: %s, want %s", strings.Join(step.args, " "), got, step.want)
		}
	}

	// A credential is sealed, never a parameter; the host and port are the
	// connection's own settings.
	for _, p := range []string{"password=hunter2", "hostname=elsewhere", "port=22", "nonsense"} {
		if err := cli("rac", "set-parameters", "-slug", "rac-"+n, "-rac-params", p); err == nil {
			t.Errorf("-rac-params %s was accepted", p)
		}
	}
	if got := value(`SELECT parameters::text FROM core.rac_connections WHERE slug = $1`, "rac-"+n); got != "{}" {
		t.Errorf("a refused -rac-params still wrote %s", got)
	}

	// Two live tokens share a name: -name must not pick one.
	err = cli("registration", "revoke", "-name", "twin-"+n)
	if err == nil || !strings.Contains(err.Error(), "-token-id") {
		t.Fatalf("an ambiguous -name was not refused with the way out: %v", err)
	}
	if got := value(`SELECT count(*)::text FROM core.registration_tokens WHERE name = $1 AND revoked_at IS NOT NULL`,
		"twin-"+n); got != "0" {
		t.Errorf("the refused revoke still revoked %s token(s)", got)
	}
	one := value(`SELECT min(id::text) FROM core.registration_tokens WHERE name = $1`, "twin-"+n)
	if err := cli("registration", "revoke", "-token-id", one); err != nil {
		t.Fatal(err)
	}
	if got := value(`SELECT count(*)::text FROM core.registration_tokens WHERE name = $1 AND revoked_at IS NOT NULL`,
		"twin-"+n); got != "1" {
		t.Errorf("-token-id revoked %s token(s), want exactly the one named", got)
	}
}

// The command names the flag for every parameter the store refuses, and
// refuses nothing the store would take: one list told two ways.
func TestEveryReservedRACParameterNamesItsFlag(t *testing.T) {
	for _, k := range store.RACReservedParameters {
		if racReservedParameters[k] == "" {
			t.Errorf("the store refuses %s and the command does not say what sets it", k)
		}
	}
	for k := range racReservedParameters {
		if !slices.Contains(store.RACReservedParameters, k) {
			t.Errorf("the command refuses %s and the store would accept it", k)
		}
	}
}
