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

// A client that has left the profile it is held to is refused without being told why, so
// doctor is where an operator hears of it (9.05). A client held to nothing is not asked.
func TestAClientOutOfItsSecurityProfileIsReported(t *testing.T) {
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
	held, free := fmt.Sprintf("held-%d", n), fmt.Sprintf("free-%d", n)
	for id, profile := range map[string]string{held: "fapi2", free: "none"} {
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash, security_profile)
			SELECT $1, id, 'P', 'public', '', $2 FROM core.organizations LIMIT 1`, id, profile); err != nil {
			t.Fatal(err)
		}
	}
	r := &Report{}
	if err := checkClientProfiles(ctx, tx.Conn(), r); err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, f := range r.Findings {
		if f.Severity == Warning && strings.Contains(f.Summary, fmt.Sprint(n)) {
			found = append(found, f.Summary)
		}
	}
	if len(found) != 1 || !strings.Contains(found[0], held) || !strings.Contains(found[0], "confidential") {
		t.Errorf("doctor said %q; want the one client out of its profile, and why", found)
	}
}
