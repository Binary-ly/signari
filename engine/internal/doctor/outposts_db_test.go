package doctor

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// An outpost that has stopped calling is an outage nobody is told about otherwise, so
// doctor names it (8.31). The kinds that are not a running process, and an outpost taken
// out of service on purpose, are silent without anything being wrong.
func TestAnOutpostThatStoppedCallingIsReported(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	n := time.Now().UnixNano()
	name := func(tag string) string { return fmt.Sprintf("%s-%d", tag, n) }
	for _, o := range []struct {
		tag, kind string
		enabled   bool
		seen      string
	}{
		{"gone", "ldap", true, "now() - interval '1 hour'"},
		{"alive", "ldap", true, "now()"},
		{"parked", "radius", false, "now() - interval '1 hour'"},
		{"kiosk", "desktop", true, "now() - interval '1 hour'"},
		{"unstarted", "ldap", true, "NULL"},
	} {
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.outposts (org_id, name, kind, token_hash, enabled, last_seen_at)
			SELECT id, $1::text, $2, sha256(convert_to($1::text, 'UTF8')), $3, `+o.seen+`
			  FROM core.organizations LIMIT 1`,
			name(o.tag), o.kind, o.enabled); err != nil {
			t.Fatal(err)
		}
	}
	r := &Report{}
	if err := checkOutposts(ctx, tx.Conn(), r); err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, f := range r.Findings {
		if f.Severity == Warning && strings.Contains(f.Summary, fmt.Sprint(n)) {
			found = append(found, f.Summary)
		}
	}
	if len(found) != 1 || !strings.Contains(found[0], name("gone")) {
		t.Errorf("doctor named %q; want the one running outpost that went quiet", found)
	}
}
